// Package sshcli lee la salida de comandos CLI de sólo lectura por una sesión
// SSH interactiva. Existe porque el CLI vía SOAP (CLI.Command) corta la
// respuesta por tamaño: "system internal security bdos statistics" sólo trae
// ~2 políticas por SOAP y completo por SSH.
package sshcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// allowed es la lista cerrada de comandos que se pueden enviar: todos son de
// sólo lectura. Además del comando, la sesión sólo envía " " (para pasar un
// --More--) y "logout".
var allowed = map[string]bool{
	"system internal security bdos statistics": true,
}

// Allowed indica si command está en la lista de comandos permitidos.
func Allowed(command string) bool { return allowed[command] }

// Config de la sesión. HostKey es la llave pública del equipo en formato
// authorized_keys (la registra "defensepro-admin ssh-trust"): sin ella no se
// conecta, para no aceptar un equipo suplantado.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	HostKey  string
	Timeout  time.Duration // toda la sesión (default 90 s)
}

type Client struct {
	cfg Config
	key ssh.PublicKey
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 90 * time.Second
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
	if err != nil {
		return nil, fmt.Errorf("llave de host SSH inválida (defensepro-admin ssh-trust): %w", err)
	}
	return &Client{cfg: cfg, key: key}, nil
}

// Límites de lo que se acepta del equipo.
const (
	maxBanner = 64 << 10 // hasta el primer prompt
	maxOutput = 16 << 20 // salida del comando (32 políticas ≈ 0,9 MB)
)

// Run ejecuta un comando permitido y devuelve su salida, sin el eco del comando
// ni el prompt final.
func (c *Client) Run(ctx context.Context, command string) (string, error) {
	if !Allowed(command) {
		return "", fmt.Errorf("comando SSH no permitido (sólo lectura): %q", command)
	}

	deadline := time.Now().Add(c.cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("ssh %s: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, clientConfig(c.cfg.User, c.cfg.Password, ssh.FixedHostKey(c.key)))
	if err != nil {
		return "", fmt.Errorf("ssh %s: %w", addr, err)
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh: sesión: %w", err)
	}
	defer sess.Close()
	// Terminal ancha para que las tablas no se partan en dos líneas.
	if err := sess.RequestPty("vt100", 500, 250, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		return "", fmt.Errorf("ssh: pty: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := sess.Shell(); err != nil {
		return "", fmt.Errorf("ssh: shell: %w", err)
	}

	t := &terminal{r: stdout, w: stdin}
	prompt, err := t.waitPrompt()
	if err != nil {
		return "", fmt.Errorf("ssh: esperando el prompt: %w", err)
	}
	if _, err := io.WriteString(stdin, command+"\n"); err != nil {
		return "", err
	}
	out, err := t.readUntilPrompt(prompt)
	if err != nil {
		return "", fmt.Errorf("ssh: leyendo la salida: %w", err)
	}
	io.WriteString(stdin, "logout\n") // best effort: cerrar la sesión limpia
	return clean(out), nil
}

func clientConfig(user, password string, hostKey ssh.HostKeyCallback) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		},
		HostKeyCallback: hostKey,
		Timeout:         15 * time.Second,
	}
}

var errGotKey = errors.New("llave obtenida")

// FetchHostKey se conecta sólo hasta recibir la llave pública del equipo (no
// se autentica). La usa "defensepro-admin ssh-trust" para registrarla.
func FetchHostKey(ctx context.Context, host string, port int) (ssh.PublicKey, error) {
	if port == 0 {
		port = 22
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	var key ssh.PublicKey
	cfg := clientConfig("probe", "", func(_ string, _ net.Addr, k ssh.PublicKey) error {
		key = k
		return errGotKey
	})
	if _, _, _, err := ssh.NewClientConn(conn, addr, cfg); key == nil {
		return nil, fmt.Errorf("ssh %s: %w", addr, err)
	}
	return key, nil
}

// terminal lee la salida de la sesión interactiva.
type terminal struct {
	r   io.Reader
	w   io.Writer
	buf []byte
}

func (t *terminal) read() error {
	chunk := make([]byte, 32<<10)
	n, err := t.r.Read(chunk)
	t.buf = append(t.buf, chunk[:n]...)
	if n > 0 {
		return nil
	}
	if err == nil {
		err = io.ErrNoProgress
	}
	return err
}

var (
	reANSI   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	rePrompt = regexp.MustCompile(`^[A-Za-z0-9_.()\-]+[#>]$`)
)

// lastLine devuelve la última línea (sin terminar) del buffer, limpia.
func lastLine(buf []byte) string {
	tail := buf[bytes.LastIndexByte(buf, '\n')+1:]
	return strings.TrimSpace(strings.ReplaceAll(reANSI.ReplaceAllString(string(tail), ""), "\r", ""))
}

// waitPrompt lee el banner hasta el primer prompt ("DefensePro#") y lo devuelve.
func (t *terminal) waitPrompt() (string, error) {
	for {
		if p := lastLine(t.buf); rePrompt.MatchString(p) {
			t.buf = t.buf[:0]
			return p, nil
		}
		if len(t.buf) > maxBanner {
			return "", fmt.Errorf("no apareció el prompt tras %d bytes", len(t.buf))
		}
		if err := t.read(); err != nil {
			return "", err
		}
	}
}

// readUntilPrompt lee la salida del comando hasta que vuelve el prompt. Si el
// equipo pagina (manage terminal more-prompt on), responde " " a cada --More--.
func (t *terminal) readUntilPrompt(prompt string) ([]byte, error) {
	for {
		switch last := lastLine(t.buf); {
		case last == prompt:
			return t.buf, nil
		case strings.HasSuffix(last, "--More--"):
			if i := bytes.LastIndex(t.buf, []byte("--More--")); i >= 0 {
				t.buf = t.buf[:i]
			}
			if _, err := io.WriteString(t.w, " "); err != nil {
				return nil, err
			}
		}
		if len(t.buf) > maxOutput {
			return nil, fmt.Errorf("la salida supera %d bytes", maxOutput)
		}
		if err := t.read(); err != nil {
			return nil, err
		}
	}
}

// clean convierte la salida a texto: los bytes no-ASCII (bordes de tabla DOS)
// quedan como runas U+0080–U+00FF, que el lector de tablas usa como
// separadores; quita secuencias ANSI, retornos de carro, el eco del comando
// (primera línea) y el prompt final (última).
func clean(raw []byte) string {
	runes := make([]rune, len(raw))
	for i, b := range raw {
		runes[i] = rune(b)
	}
	text := strings.ReplaceAll(reANSI.ReplaceAllString(string(runes), ""), "\r", "")
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[i+1:]
	}
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	return text
}
