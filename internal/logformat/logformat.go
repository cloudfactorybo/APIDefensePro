package logformat

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// NewFormatter devuelve el formatter según el parámetro:
//
//	"json" — logrus JSONFormatter (para pipelines de ingesta)
//	"text" o vacío — formato humano alineado (default)
func NewFormatter(kind string) logrus.Formatter {
	if strings.EqualFold(kind, "json") {
		return &logrus.JSONFormatter{TimestampFormat: time.RFC3339}
	}
	return &textFormatter{}
}

type textFormatter struct{}

// Ejemplo de salida:
//   18:48:07  INFO   GET  /api/v1/monitoring         200  14ms    req=f25eeafb client=172.18.0.1 bytes=591
//   18:48:29  INFO   warmup system                                            ok=2 errors=0 duration=3.02s
//   18:50:05  ERROR  defensepro call failed                                   device=DP1 endpoint=system err="auth 401"
func (f *textFormatter) Format(e *logrus.Entry) ([]byte, error) {
	var b bytes.Buffer

	// hora
	b.WriteString(e.Time.UTC().Format("15:04:05"))
	b.WriteString("  ")

	// nivel, padded a 5 chars
	fmt.Fprintf(&b, "%-5s  ", levelAbbr(e.Level))

	method, hasMethod := e.Data["method"].(string)
	path, hasPath := e.Data["path"].(string)

	if hasMethod && hasPath {
		f.writeHTTPLine(&b, e, method, path)
	} else {
		f.writeGenericLine(&b, e)
	}

	b.WriteByte('\n')
	return b.Bytes(), nil
}

// Formato request HTTP: método, path, status, duración, y fields extras ordenados.
func (f *textFormatter) writeHTTPLine(b *bytes.Buffer, e *logrus.Entry, method, path string) {
	status := intVal(e.Data["status"])
	dur := humanDuration(floatVal(e.Data["duration_ms"]))

	fmt.Fprintf(b, "%-4s %-30s %3d  %-7s", method, path, status, dur)

	extras := filter(e.Data, "method", "path", "status", "duration_ms")
	if len(extras) > 0 {
		b.WriteString("  ")
		writeFieldsOrdered(b, extras, []string{"req_id", "client", "bytes", "user_agent"})
	}
}

// Formato genérico: mensaje + fields ordenados.
func (f *textFormatter) writeGenericLine(b *bytes.Buffer, e *logrus.Entry) {
	// padding de mensaje para que los fields queden alineados como columna
	const msgPad = 40
	msg := e.Message
	if err, ok := e.Data[logrus.ErrorKey]; ok && err != nil {
		msg = fmt.Sprintf("%s: %v", msg, err)
	}
	b.WriteString(msg)
	for i := len(msg); i < msgPad; i++ {
		b.WriteByte(' ')
	}

	// transforma duration_ms → duration
	data := make(logrus.Fields, len(e.Data))
	for k, v := range e.Data {
		if k == logrus.ErrorKey {
			continue
		}
		if k == "duration_ms" {
			data["duration"] = humanDuration(floatVal(v))
		} else {
			data[k] = v
		}
	}

	if len(data) > 0 {
		b.WriteString("  ")
		// Campos frecuentes primero, resto alfabético
		preferred := []string{"device", "endpoint", "op", "req_id", "count", "prev", "ok", "errors", "addr"}
		writeFieldsOrdered(b, data, preferred)
	}
}

func levelAbbr(l logrus.Level) string {
	switch l {
	case logrus.PanicLevel:
		return "PANIC"
	case logrus.FatalLevel:
		return "FATAL"
	case logrus.ErrorLevel:
		return "ERROR"
	case logrus.WarnLevel:
		return "WARN"
	case logrus.InfoLevel:
		return "INFO"
	case logrus.DebugLevel:
		return "DEBUG"
	case logrus.TraceLevel:
		return "TRACE"
	}
	return strings.ToUpper(l.String())
}

func humanDuration(ms float64) string {
	switch {
	case ms >= 1000:
		return fmt.Sprintf("%.2fs", ms/1000)
	case ms >= 1:
		return fmt.Sprintf("%.0fms", ms)
	default:
		return fmt.Sprintf("%.2fms", ms)
	}
}

func writeFieldsOrdered(b *bytes.Buffer, fields logrus.Fields, preferred []string) {
	used := map[string]bool{}
	first := true
	emit := func(k string, v interface{}) {
		if !first {
			b.WriteByte(' ')
		}
		fmt.Fprintf(b, "%s=%s", k, renderValue(v))
		first = false
	}

	for _, k := range preferred {
		if v, ok := fields[k]; ok {
			emit(k, v)
			used[k] = true
		}
	}

	rest := make([]string, 0)
	for k := range fields {
		if !used[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		emit(k, fields[k])
	}
}

func renderValue(v interface{}) string {
	s := fmt.Sprint(v)
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, " \t\"") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func filter(data logrus.Fields, exclude ...string) logrus.Fields {
	skip := make(map[string]bool, len(exclude))
	for _, k := range exclude {
		skip[k] = true
	}
	out := make(logrus.Fields, len(data))
	for k, v := range data {
		if !skip[k] {
			out[k] = v
		}
	}
	return out
}

func intVal(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	}
	return 0
}

func floatVal(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	}
	return 0
}
