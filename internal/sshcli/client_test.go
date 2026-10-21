package sshcli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestAllowed(t *testing.T) {
	if !Allowed("system internal security bdos statistics") {
		t.Error("el comando de estadísticas BDoS debe estar permitido")
	}
	for _, cmd := range []string{
		"", "reboot", "manage terminal more-prompt set off",
		"system internal security bdos statistics; reboot",
		"system internal security bdos statistics\nreboot",
		"System Internal Security BDoS Statistics",
	} {
		if Allowed(cmd) {
			t.Errorf("%q NO debería estar permitido", cmd)
		}
	}
}

// La barrera actúa antes de abrir la conexión.
func TestRunRejectsBeforeNetwork(t *testing.T) {
	c := testClient(t, "192.0.2.1", 22, mustSigner(t).PublicKey())
	if _, err := c.Run(context.Background(), "reboot"); err == nil || !strings.Contains(err.Error(), "no permitido") {
		t.Errorf("Run = %v, want error de comando no permitido", err)
	}
}

func TestNewClientRequiresHostKey(t *testing.T) {
	if _, err := NewClient(Config{Host: "x", User: "u", Password: "p"}); err == nil {
		t.Error("sin llave de host no debe crear el cliente")
	}
}

// fakeDP es un servidor SSH que imita el CLI del DefensePro: banner, prompt,
// eco del comando, salida paginada con --More-- y prompt final.
func fakeDP(t *testing.T, signer ssh.Signer, output string, pageLines int) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if c.User() == "soap-ro" && string(pass) == "secreto" {
			return nil, nil
		}
		return nil, ssh.ErrNoAuth
	}}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, cfg, output, pageLines)
		}
	}()
	h, p, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.Atoi(p)
	return h, n
}

func serve(conn net.Conn, cfg *ssh.ServerConfig, output string, pageLines int) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range chReqs {
				r.Reply(r.Type == "pty-req" || r.Type == "shell", nil)
			}
		}()
		in := bufio.NewReader(ch)
		ch.Write([]byte("\r\n      radware\r\n\r\n\x1b[0mDefensePro#"))
		for {
			line, err := in.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			ch.Write([]byte(cmd + "\r\n"))
			if cmd == "logout" {
				ch.Close()
				return
			}
			lines := strings.Split(output, "\n")
			for i, l := range lines {
				ch.Write([]byte(l + "\r\n"))
				if pageLines > 0 && (i+1)%pageLines == 0 && i+1 < len(lines) {
					ch.Write([]byte("--More--"))
					if b, err := in.ReadByte(); err != nil || b != ' ' {
						return
					}
					ch.Write([]byte("\r        \r"))
				}
			}
			ch.Write([]byte("DefensePro#"))
		}
	}
}

func TestRunAgainstFakeDefensePro(t *testing.T) {
	signer := mustSigner(t)
	// Bordes de tabla DOS (bytes no-ASCII) como los manda el equipo.
	var sb strings.Builder
	for i := 1; i <= 32; i++ {
		sb.WriteString("policy name - Pol_" + strconv.Itoa(i) + " \n")
		sb.WriteString("\xb3UDP         \xb3       500\xb3\n")
	}
	output := strings.TrimSuffix(sb.String(), "\n")

	for _, page := range []int{0, 7} { // sin paginar y con --More-- cada 7 líneas
		host, port := fakeDP(t, signer, output, page)
		c := testClient(t, host, port, signer.PublicKey())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		got, err := c.Run(ctx, "system internal security bdos statistics")
		cancel()
		if err != nil {
			t.Fatalf("página %d: %v", page, err)
		}
		if n := strings.Count(got, "policy name - "); n != 32 {
			t.Errorf("página %d: %d políticas, want 32", page, n)
		}
		if strings.Contains(got, "--More--") || strings.Contains(got, "DefensePro#") || strings.Contains(got, "\r") {
			t.Errorf("página %d: quedó basura de terminal: %q", page, got[:min(len(got), 200)])
		}
		if !strings.Contains(got, "³UDP") {
			t.Errorf("página %d: los bordes no-ASCII deben quedar como runas U+00B3", page)
		}
	}
}

// Una llave de host distinta a la registrada corta la conexión.
func TestRunRejectsUnknownHostKey(t *testing.T) {
	host, port := fakeDP(t, mustSigner(t), "x", 0)
	c := testClient(t, host, port, mustSigner(t).PublicKey()) // otra llave
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Run(ctx, "system internal security bdos statistics"); err == nil {
		t.Fatal("debió rechazar una llave de host distinta")
	}
}

func TestFetchHostKey(t *testing.T) {
	signer := mustSigner(t)
	host, port := fakeDP(t, signer, "x", 0)
	key, err := FetchHostKey(context.Background(), host, port)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(key) != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Error("la llave obtenida no es la del servidor")
	}
}

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testClient(t *testing.T, host string, port int, key ssh.PublicKey) *Client {
	t.Helper()
	c, err := NewClient(Config{
		Host: host, Port: port, User: "soap-ro", Password: "secreto",
		HostKey: string(ssh.MarshalAuthorizedKey(key)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
