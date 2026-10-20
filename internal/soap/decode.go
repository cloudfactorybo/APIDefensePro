package soap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// Node es un elemento XML genérico. Se usa en vez de structs fijos porque en
// RPC/encoded los nombres de los wrappers y de los ítems de arrays varían según
// el servidor, y puede haber referencias multiRef (href="#id") a resolver.
type Node struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Text     string     `xml:",chardata"`
	Children []Node     `xml:",any"`
}

func (n *Node) attr(local string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == local {
			return a.Value
		}
	}
	return ""
}

func (n *Node) child(local string) *Node {
	for i := range n.Children {
		if n.Children[i].XMLName.Local == local {
			return &n.Children[i]
		}
	}
	return nil
}

// Value devuelve el texto del elemento sin espacios; "" si es xsi:nil.
func (n *Node) Value() string {
	if n.attr("nil") == "true" {
		return ""
	}
	return strings.TrimSpace(n.Text)
}

// Fault es un SOAP Fault devuelto por el equipo (operación inexistente en esa
// versión, parámetro inválido, etc.). Indica que el equipo SÍ respondió.
type Fault struct {
	Code   string
	String string
	Detail string
}

func (f *Fault) Error() string {
	msg := "soap fault"
	if f.Code != "" {
		msg += " " + f.Code
	}
	if f.String != "" {
		msg += ": " + f.String
	}
	if f.Detail != "" {
		msg += " (" + f.Detail + ")"
	}
	return msg
}

// Response es el wrapper de respuesta de una operación (<op>Response) con sus
// partes ya resueltas (value, table, status, entry...).
type Response struct {
	Op    string
	Parts []Node
}

// Row es una fila de tabla: nombre de campo → valor en texto.
type Row map[string]string

// Decode interpreta el XML de respuesta. Devuelve *Fault si el cuerpo es un
// SOAP Fault.
func Decode(body []byte) (*Response, error) {
	var env Node
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.CharsetReader = charsetReader
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("xml inválido: %w", err)
	}
	if env.XMLName.Local != "Envelope" {
		return nil, fmt.Errorf("respuesta no es un sobre SOAP (<%s>): %s", env.XMLName.Local, snippet(body))
	}
	b := env.child("Body")
	if b == nil {
		return nil, fmt.Errorf("sobre SOAP sin Body")
	}

	ids := map[string]*Node{}
	indexIDs(b, ids)

	var wrapper *Node
	for i := range b.Children {
		c := &b.Children[i]
		if c.XMLName.Local == "Fault" {
			return nil, faultFrom(c)
		}
		// Los multiRef van como hermanos del wrapper, todos con id.
		if wrapper == nil && c.attr("id") == "" {
			wrapper = c
		}
	}
	if wrapper == nil {
		return nil, fmt.Errorf("sobre SOAP sin respuesta")
	}

	resolveRefs(wrapper, ids, 0)
	return &Response{Op: wrapper.XMLName.Local, Parts: wrapper.Children}, nil
}

// Part busca una parte por nombre; si no existe devuelve nil.
func (r *Response) Part(name string) *Node {
	for i := range r.Parts {
		if r.Parts[i].XMLName.Local == name {
			return &r.Parts[i]
		}
	}
	return nil
}

// Value devuelve el valor escalar de una operación get_X (parte "value").
func (r *Response) Value() (string, error) {
	if p := r.Part("value"); p != nil {
		return p.Value(), nil
	}
	if len(r.Parts) == 0 {
		return "", fmt.Errorf("%s: respuesta sin valor", r.Op)
	}
	return r.Parts[0].Value(), nil
}

// Table devuelve las filas de una operación getAll_X (parte "table"). Una tabla
// vacía devuelve nil sin error.
func (r *Response) Table() ([]Row, error) {
	t := r.Part("table")
	if t == nil {
		for i := range r.Parts {
			if len(r.Parts[i].Children) > 0 {
				t = &r.Parts[i]
				break
			}
		}
	}
	if t == nil {
		if r.Part("status") != nil {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: respuesta sin tabla", r.Op)
	}

	rows := make([]Row, 0, len(t.Children))
	for i := range t.Children {
		item := &t.Children[i]
		row := make(Row, len(item.Children))
		for j := range item.Children {
			f := &item.Children[j]
			row[f.XMLName.Local] = f.Value()
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// charsetReader convierte a UTF-8 las respuestas en ISO-8859-1, que es lo que
// declara el DefensePro. Cada byte Latin-1 equivale al code point Unicode del
// mismo valor, así que no hace falta una tabla de conversión.
func charsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return input, nil
	case "iso-8859-1", "iso8859-1", "iso_8859-1", "latin1", "latin-1", "l1":
		raw, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		b.Grow(len(raw))
		for _, c := range raw {
			b.WriteRune(rune(c))
		}
		return strings.NewReader(b.String()), nil
	}
	return nil, fmt.Errorf("charset no soportado: %s", label)
}

func indexIDs(n *Node, ids map[string]*Node) {
	for i := range n.Children {
		c := &n.Children[i]
		if id := c.attr("id"); id != "" {
			ids[id] = c
		}
		indexIDs(c, ids)
	}
}

// resolveRefs reemplaza los elementos href="#id" por el contenido referenciado.
// depth evita ciclos en respuestas mal formadas.
func resolveRefs(n *Node, ids map[string]*Node, depth int) {
	if depth > 32 {
		return
	}
	for i := range n.Children {
		c := &n.Children[i]
		if href := c.attr("href"); strings.HasPrefix(href, "#") {
			if target, ok := ids[href[1:]]; ok {
				c.Text = target.Text
				c.Children = append([]Node(nil), target.Children...)
			}
		}
		resolveRefs(c, ids, depth+1)
	}
}

func faultFrom(n *Node) *Fault {
	f := &Fault{}
	if c := n.child("faultcode"); c != nil {
		f.Code = c.Value()
	}
	if c := n.child("faultstring"); c != nil {
		f.String = c.Value()
	}
	if c := n.child("detail"); c != nil {
		f.Detail = strings.TrimSpace(c.Value())
	}
	return f
}

// parseFault intenta leer un Fault de un cuerpo no-200; nil si no lo es.
func parseFault(body []byte) *Fault {
	_, err := Decode(body)
	if f, ok := err.(*Fault); ok {
		return f
	}
	return nil
}

// DecodeRows convierte filas en structs según el tag `soap:"Campo"` de cada
// campo. Soporta string, enteros, float y bool. Es tolerante: un valor que no
// parsea (p.ej. "N/A" en un campo numérico) deja el cero del tipo.
func DecodeRows[T any](rows []Row) []T {
	out := make([]T, len(rows))
	if len(rows) == 0 {
		return out
	}
	t := reflect.TypeFor[T]()
	type mapped struct {
		index int
		name  string
	}
	var fields []mapped
	for i := 0; i < t.NumField(); i++ {
		if tag := t.Field(i).Tag.Get("soap"); tag != "" {
			fields = append(fields, mapped{i, tag})
		}
	}
	for i, row := range rows {
		v := reflect.ValueOf(&out[i]).Elem()
		for _, f := range fields {
			if raw, ok := row[f.name]; ok {
				setField(v.Field(f.index), raw)
			}
		}
	}
	return out
}

// SetValue copia un valor escalar en dst (*string, *int64, *int o *float64).
func SetValue(dst any, raw string) {
	v := reflect.ValueOf(dst)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	setField(v.Elem(), raw)
}

func setField(f reflect.Value, raw string) {
	switch f.Kind() {
	case reflect.String:
		f.SetString(raw)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			f.SetInt(n)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil {
			f.SetUint(n)
		}
	case reflect.Float32, reflect.Float64:
		if n, err := strconv.ParseFloat(raw, 64); err == nil {
			f.SetFloat(n)
		}
	case reflect.Bool:
		if b, err := strconv.ParseBool(raw); err == nil {
			f.SetBool(b)
		}
	}
}
