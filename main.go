// redact.sql — SQL Schema Obfuscator
//
// Copyright (C) 2026  Przemysław Malkowski
// MIT License
//
// Generalizes SQL schema definitions (MySQL / PostgreSQL) by replacing
// sensitive identifiers — table, column, index, constraint, sequence, type and
// schema names — with neutral, consistent placeholders, while preserving the
// foreign-key relationships between them. Data rows, comments and anything that
// can't be safely transformed are dropped so nothing sensitive leaks.
//
// It runs two ways:
//
//	Web UI:  run with no piped input  ->  http://127.0.0.1:8585
//	CLI:     cat dump.sql | redactsql [-o out.sql] [-remove-fk] ...
//
// Everything happens locally and in memory. Nothing is sent or stored anywhere.
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

const version = "0.1.0"

//go:embed index.html
var assets embed.FS

// ---------------------------------------------------------------------------
// Options & report
// ---------------------------------------------------------------------------

type Options struct {
	RemoveFK bool
	KeepID   bool
	Dialect  string // "auto" | "mysql" | "postgres"
}

type Report struct {
	Tables      int            `json:"tables"`
	Columns     int            `json:"columns"`
	Indexes     int            `json:"indexes"`
	Constraints int            `json:"constraints"`
	Sequences   int            `json:"sequences"`
	Types       int            `json:"types"`
	Schemas     int            `json:"schemas"`
	Dropped     map[string]int `json:"dropped"`
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

const (
	kIdent  = iota // bare identifier or keyword
	kQIdent        // quoted identifier: `back`, "double"
	kString        // string literal incl. quotes, or dollar-quoted body
	kNum           // numeric literal
	kPunct         // punctuation / operator
)

type tok struct {
	kind  int
	text  string // ident/qident: the (unquoted) value; others: raw text
	quote byte   // qident quote char: '`' or '"'
}

func (t tok) lower() string {
	if t.kind == kIdent {
		return strings.ToLower(t.text)
	}
	return ""
}
func (t tok) isWord(w string) bool  { return t.kind == kIdent && strings.EqualFold(t.text, w) }
func (t tok) isPunct(p string) bool { return t.kind == kPunct && t.text == p }

func isDigit(c byte) bool      { return c >= '0' && c <= '9' }
func isLetter(c byte) bool     { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isIdentStart(c byte) bool { return isLetter(c) || c == '_' || c >= 0x80 }
func isIdentPart(c byte) bool  { return isLetter(c) || isDigit(c) || c == '_' || c >= 0x80 }

// readQuoted scans a '...'-style literal starting at i (s[i]==q), honoring both
// doubled quotes ('') and backslash escapes. Returns the index past the close.
func readQuoted(s string, i int, q byte) (int, string) {
	start := i
	i++
	for i < len(s) {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i += 2
			continue
		}
		if c == q {
			if i+1 < len(s) && s[i+1] == q {
				i += 2
				continue
			}
			i++
			break
		}
		i++
	}
	return i, s[start:i]
}

// skipQuoteSimple scans a quoted run that only uses doubling to escape (backtick,
// ANSI double-quote). Returns the index past the close.
func skipQuoteSimple(s string, i int) int {
	q := s[i]
	i++
	for i < len(s) {
		if s[i] == q {
			if i+1 < len(s) && s[i+1] == q {
				i += 2
				continue
			}
			i++
			break
		}
		i++
	}
	return i
}

// readDollar matches a PostgreSQL dollar-quoted string ($tag$ ... $tag$).
func readDollar(s string, i int) (string, int, bool) {
	j := i + 1
	for j < len(s) && isIdentPart(s[j]) {
		j++
	}
	if j >= len(s) || s[j] != '$' {
		return "", 0, false
	}
	tag := s[i : j+1]
	k := j + 1
	for k < len(s) {
		if s[k] == '$' && strings.HasPrefix(s[k:], tag) {
			return tag, k + len(tag), true
		}
		k++
	}
	return "", 0, false
}

func unquoteSQLString(raw string) string {
	if len(raw) >= 2 && raw[0] == '\'' {
		inner := raw[1 : len(raw)-1]
		inner = strings.ReplaceAll(inner, "''", "'")
		inner = strings.ReplaceAll(inner, "\\'", "'")
		return inner
	}
	return raw
}

// tokenize turns a single (comment-free) statement into tokens, dropping
// whitespace. mysqlQuotes treats "..." as a string rather than an identifier.
func tokenize(s string, mysqlQuotes bool) []tok {
	var out []tok
	i, n := 0, len(s)
	for i < n {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '`':
			j := i + 1
			var b strings.Builder
			for j < n {
				if s[j] == '`' {
					if j+1 < n && s[j+1] == '`' {
						b.WriteByte('`')
						j += 2
						continue
					}
					j++
					break
				}
				b.WriteByte(s[j])
				j++
			}
			out = append(out, tok{kind: kQIdent, text: b.String(), quote: '`'})
			i = j
		case c == '"':
			if mysqlQuotes {
				j, raw := readQuoted(s, i, '"')
				out = append(out, tok{kind: kString, text: raw})
				i = j
				continue
			}
			j := i + 1
			var b strings.Builder
			for j < n {
				if s[j] == '"' {
					if j+1 < n && s[j+1] == '"' {
						b.WriteByte('"')
						j += 2
						continue
					}
					j++
					break
				}
				b.WriteByte(s[j])
				j++
			}
			out = append(out, tok{kind: kQIdent, text: b.String(), quote: '"'})
			i = j
		case c == '\'':
			j, raw := readQuoted(s, i, '\'')
			out = append(out, tok{kind: kString, text: raw})
			i = j
		case c == '$':
			if _, end, ok := readDollar(s, i); ok {
				out = append(out, tok{kind: kString, text: s[i:end]})
				i = end
				continue
			}
			out = append(out, tok{kind: kPunct, text: "$"})
			i++
		case c == ':' && i+1 < n && s[i+1] == ':':
			out = append(out, tok{kind: kPunct, text: "::"})
			i += 2
		case isDigit(c) || (c == '.' && i+1 < n && isDigit(s[i+1])):
			j := i
			for j < n {
				d := s[j]
				if isDigit(d) || d == '.' || d == 'e' || d == 'E' || d == 'x' || (d >= 'a' && d <= 'f') || (d >= 'A' && d <= 'F') ||
					((d == '+' || d == '-') && j > i && (s[j-1] == 'e' || s[j-1] == 'E')) {
					j++
					continue
				}
				break
			}
			out = append(out, tok{kind: kNum, text: s[i:j]})
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < n && isIdentPart(s[j]) {
				j++
			}
			out = append(out, tok{kind: kIdent, text: s[i:j]})
			i = j
		default:
			out = append(out, tok{kind: kPunct, text: string(c)})
			i++
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Statement splitting (comment / quote / dollar aware)
// ---------------------------------------------------------------------------

func atLineStart(s string, i int) bool {
	for j := i - 1; j >= 0; j-- {
		c := s[j]
		if c == '\n' {
			return true
		}
		if c == ' ' || c == '\t' || c == '\r' {
			continue
		}
		return false
	}
	return true
}

// stripCopyBlocks removes PostgreSQL "COPY ... FROM stdin;" data blocks, whose
// data lines are terminated by a lone "\." rather than a semicolon.
func stripCopyBlocks(sql string) string {
	lines := strings.Split(sql, "\n")
	out := make([]string, 0, len(lines))
	skip := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if skip {
			if t == `\.` {
				skip = false
			}
			continue
		}
		up := strings.ToUpper(t)
		if strings.HasPrefix(up, "COPY ") && strings.Contains(up, " FROM STDIN") {
			skip = true
			continue // drop the COPY header too
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func splitStatements(sql string) []string {
	var stmts []string
	var b strings.Builder
	flush := func() {
		if s := strings.TrimSpace(b.String()); s != "" {
			stmts = append(stmts, s)
		}
		b.Reset()
	}
	i, n := 0, len(sql)
	for i < n {
		c := sql[i]
		switch {
		case c == '-' && i+1 < n && sql[i+1] == '-':
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '#' && atLineStart(sql, i):
			for i < n && sql[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < n && sql[i+1] == '*':
			i += 2
			depth := 1
			for i < n && depth > 0 {
				if sql[i] == '/' && i+1 < n && sql[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if sql[i] == '*' && i+1 < n && sql[i+1] == '/' {
					depth--
					i += 2
					continue
				}
				i++
			}
		case c == '\'':
			j, _ := readQuoted(sql, i, '\'')
			b.WriteString(sql[i:j])
			i = j
		case c == '"' || c == '`':
			j := skipQuoteSimple(sql, i)
			b.WriteString(sql[i:j])
			i = j
		case c == '$':
			if _, end, ok := readDollar(sql, i); ok {
				b.WriteString(sql[i:end])
				i = end
				continue
			}
			b.WriteByte(c)
			i++
		case c == ';':
			flush()
			i++
		default:
			b.WriteByte(c)
			i++
		}
	}
	flush()
	return stmts
}

// ---------------------------------------------------------------------------
// Token cursor & small parse helpers
// ---------------------------------------------------------------------------

type cur struct {
	t []tok
	i int
}

func (c *cur) eof() bool { return c.i >= len(c.t) }
func (c *cur) peek() tok {
	if c.eof() {
		return tok{}
	}
	return c.t[c.i]
}
func (c *cur) at(o int) tok {
	if c.i+o < 0 || c.i+o >= len(c.t) {
		return tok{}
	}
	return c.t[c.i+o]
}
func (c *cur) next() tok {
	t := c.peek()
	c.i++
	return t
}
func (c *cur) isWord(w string) bool  { return c.peek().isWord(w) }
func (c *cur) isPunct(p string) bool { return c.peek().isPunct(p) }
func (c *cur) takeWord(w string) bool {
	if c.isWord(w) {
		c.i++
		return true
	}
	return false
}
func (c *cur) takePunct(p string) bool {
	if c.isPunct(p) {
		c.i++
		return true
	}
	return false
}
func (c *cur) skipUntil(w string) {
	for !c.eof() && !c.peek().isWord(w) {
		c.next()
	}
}
func (c *cur) isName() bool {
	k := c.peek().kind
	return k == kIdent || k == kQIdent
}

type ident struct {
	quote byte
	val   string
}

func identOf(t tok) ident {
	if t.kind == kQIdent {
		return ident{quote: t.quote, val: t.text}
	}
	return ident{val: t.text}
}
func (id ident) render(newVal string) string {
	switch id.quote {
	case '`':
		return "`" + newVal + "`"
	case '"':
		return `"` + newVal + `"`
	default:
		return newVal
	}
}

func lastVal(parts []ident) string {
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1].val
}

func readQualified(c *cur) []ident {
	var parts []ident
	if !c.isName() {
		return parts
	}
	parts = append(parts, identOf(c.next()))
	for c.isPunct(".") {
		c.next()
		if c.isName() {
			parts = append(parts, identOf(c.next()))
		} else {
			break
		}
	}
	return parts
}

// readParen expects the cursor at "(" and returns the tokens inside the matching
// pair (outer parens excluded), advancing past the closing ")".
func readParen(c *cur) ([]tok, bool) {
	if !c.takePunct("(") {
		return nil, false
	}
	var inner []tok
	depth := 1
	for !c.eof() {
		t := c.next()
		if t.isPunct("(") {
			depth++
		} else if t.isPunct(")") {
			depth--
			if depth == 0 {
				return inner, true
			}
		}
		inner = append(inner, t)
	}
	return inner, true
}

func splitTopComma(toks []tok) [][]tok {
	var res [][]tok
	var cur []tok
	depth := 0
	for _, t := range toks {
		if t.isPunct("(") {
			depth++
		}
		if t.isPunct(")") {
			depth--
		}
		if depth == 0 && t.isPunct(",") {
			res = append(res, cur)
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	if len(cur) > 0 {
		res = append(res, cur)
	}
	return res
}

// ---------------------------------------------------------------------------
// Keyword / type / function vocabularies
// ---------------------------------------------------------------------------

func makeSet(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

var flagKeywords = makeSet(
	"not", "null", "default", "primary", "key", "unique", "foreign", "references",
	"check", "on", "delete", "update", "cascade", "restrict", "no", "action",
	"match", "full", "partial", "simple", "deferrable", "initially", "deferred",
	"immediate", "collate", "using", "generated", "always", "stored", "virtual",
	"and", "or", "as", "unsigned", "zerofill", "auto_increment", "engine",
	"charset", "row_format", "comment", "constraint", "add", "column", "alter",
	"drop", "set", "type", "table", "index", "owned", "by", "where", "asc",
	"desc", "nulls", "first", "last", "enforced", "in", "is", "between", "like",
	"distinct", "start", "increment", "minvalue", "maxvalue", "cache", "cycle",
	"restart", "sequence", "exists", "if",
)

var typeWords = makeSet(
	"int", "integer", "int2", "int4", "int8", "smallint", "bigint", "tinyint",
	"mediumint", "decimal", "numeric", "float", "float4", "float8", "double",
	"real", "bit", "bool", "boolean", "char", "varchar", "character", "varying",
	"nchar", "nvarchar", "text", "tinytext", "mediumtext", "longtext", "blob",
	"tinyblob", "mediumblob", "longblob", "bytea", "binary", "varbinary",
	"date", "datetime", "timestamp", "timestamptz", "time", "timetz", "year",
	"json", "jsonb", "uuid", "enum", "money", "inet", "cidr", "macaddr", "xml",
	"interval", "geometry", "point", "precision", "serial", "bigserial",
	"smallserial", "national",
)

var funcWords = makeSet(
	"nextval", "setval", "currval", "lower", "upper", "coalesce", "now", "trim",
	"length", "abs", "round", "date_trunc", "to_char", "to_timestamp", "concat",
	"md5", "substr", "substring", "cast", "count", "sum", "max", "min",
)

var constraintLead = makeSet(
	"primary", "unique", "key", "index", "fulltext", "spatial", "foreign",
	"check", "constraint", "exclude", "period",
)

var fkActionSet = makeSet(
	"on", "delete", "update", "cascade", "restrict", "set", "null", "default",
	"no", "action", "match", "full", "partial", "simple", "deferrable",
	"initially", "deferred", "immediate", "enforced",
)

var wellKnownSchemas = makeSet(
	"public", "pg_catalog", "information_schema", "mysql", "sys",
	"performance_schema", "dbo", "pg_temp",
)

func isFlagKeyword(lo string) bool    { return flagKeywords[lo] }
func isTypeWord(lo string) bool       { return typeWords[lo] }
func isTypeOrFunc(lo string) bool     { return typeWords[lo] || funcWords[lo] }
func isWellKnown(lo string) bool      { return wellKnownSchemas[lo] }
func isConstraintLead(lo string) bool { return constraintLead[lo] }

func stdTypePrefix(first, second string) (string, bool) {
	switch first {
	case "int", "integer", "int4":
		return "int", true
	case "int8", "bigint":
		return "bigint", true
	case "int2", "smallint":
		return "smallint", true
	case "tinyint":
		return "tinyint", true
	case "mediumint":
		return "mediumint", true
	case "serial", "serial4":
		return "serial", true
	case "bigserial", "serial8":
		return "bigserial", true
	case "smallserial", "serial2":
		return "smallserial", true
	case "decimal", "numeric":
		return "decimal", true
	case "float", "float4":
		return "float", true
	case "double", "float8":
		return "double", true
	case "real":
		return "real", true
	case "bit":
		return "bit", true
	case "bool", "boolean":
		return "bool", true
	case "char":
		return "char", true
	case "character":
		if second == "varying" {
			return "varchar", true
		}
		return "char", true
	case "varchar":
		return "varchar", true
	case "nvarchar":
		return "nvarchar", true
	case "nchar":
		return "nchar", true
	case "text", "tinytext", "mediumtext", "longtext":
		return first, true
	case "blob", "tinyblob", "mediumblob", "longblob", "bytea":
		return first, true
	case "binary":
		return "binary", true
	case "varbinary":
		return "varbinary", true
	case "date":
		return "date", true
	case "datetime":
		return "datetime", true
	case "timestamp", "timestamptz":
		return "timestamp", true
	case "time", "timetz":
		return "time", true
	case "year":
		return "year", true
	case "json", "jsonb":
		return first, true
	case "uuid":
		return "uuid", true
	case "enum":
		return "enum", true
	case "set":
		return "set", true
	case "money":
		return "money", true
	case "inet", "cidr", "macaddr":
		return first, true
	case "xml":
		return "xml", true
	case "interval":
		return "interval", true
	case "geometry", "point":
		return first, true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Parsed statement structures
// ---------------------------------------------------------------------------

type column struct {
	name     ident
	typeToks []tok
}

type consItem struct {
	kind           string
	word           string
	constraintName *ident
	name           *ident
	cols           []tok
	refTable       []ident
	refCols        []tok
	actionToks     []tok
	exprToks       []tok
}

func (cs *consItem) isFK() bool { return cs.kind == "FOREIGN" }

type createTable struct {
	qual    []ident
	tail    []tok
	columns []*column
	cons    []*consItem
}

type createIndex struct {
	unique   bool
	kindWord string
	name     *ident
	table    []ident
	method   string
	parts    []tok
	where    []tok
}

type alterTable struct {
	only    bool
	table   []ident
	actions [][]tok
}

type createSequence struct {
	qual []ident
	opts []tok
}

type alterSequence struct {
	seq   []ident
	owned []ident
}

type createType struct {
	qual   []ident
	isEnum bool
	vals   []tok
}

type createSchema struct {
	name ident
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

func parseColumn(it []tok) *column {
	return &column{name: identOf(it[0]), typeToks: it[1:]}
}

func parseConsItem(it []tok) *consItem {
	c := &cur{t: it}
	cs := &consItem{}
	if c.takeWord("constraint") {
		if c.isName() {
			id := identOf(c.next())
			cs.constraintName = &id
		}
	}
	switch {
	case c.takeWord("primary"):
		c.takeWord("key")
		cs.kind = "PRIMARY"
		cs.cols, _ = readParen(c)
	case c.takeWord("unique"):
		cs.kind = "UNIQUE"
		if c.isWord("key") {
			cs.word = "KEY"
			c.next()
		} else if c.isWord("index") {
			cs.word = "INDEX"
			c.next()
		}
		if !c.isPunct("(") && c.isName() {
			id := identOf(c.next())
			cs.name = &id
		}
		cs.cols, _ = readParen(c)
	case c.isWord("key") || c.isWord("index"):
		cs.kind = "INDEX"
		if c.isWord("key") {
			cs.word = "KEY"
		} else {
			cs.word = "INDEX"
		}
		c.next()
		if !c.isPunct("(") && c.isName() {
			id := identOf(c.next())
			cs.name = &id
		}
		cs.cols, _ = readParen(c)
	case c.isWord("fulltext") || c.isWord("spatial"):
		cs.kind = strings.ToUpper(c.peek().text)
		c.next()
		if c.isWord("key") {
			cs.word = "KEY"
			c.next()
		} else if c.isWord("index") {
			cs.word = "INDEX"
			c.next()
		}
		if !c.isPunct("(") && c.isName() {
			id := identOf(c.next())
			cs.name = &id
		}
		cs.cols, _ = readParen(c)
	case c.takeWord("foreign"):
		cs.kind = "FOREIGN"
		c.takeWord("key")
		if !c.isPunct("(") && c.isName() {
			id := identOf(c.next())
			cs.name = &id
		}
		cs.cols, _ = readParen(c)
		c.takeWord("references")
		cs.refTable = readQualified(c)
		if c.isPunct("(") {
			cs.refCols, _ = readParen(c)
		}
		cs.actionToks = c.t[c.i:]
	case c.takeWord("check"):
		cs.kind = "CHECK"
		cs.exprToks, _ = readParen(c)
	default:
		cs.kind = "GENERIC"
		cs.exprToks = it
	}
	return cs
}

func parseCreateTable(toks []tok) *createTable {
	c := &cur{t: toks}
	c.skipUntil("table")
	c.takeWord("table")
	if c.takeWord("if") {
		c.takeWord("not")
		c.takeWord("exists")
	}
	qual := readQualified(c)
	inner, ok := readParen(c)
	if !ok {
		return nil
	}
	ct := &createTable{qual: qual, tail: c.t[c.i:]}
	for _, it := range splitTopComma(inner) {
		if len(it) == 0 {
			continue
		}
		first := it[0]
		if first.kind == kQIdent {
			ct.columns = append(ct.columns, parseColumn(it))
			continue
		}
		if isConstraintLead(first.lower()) {
			ct.cons = append(ct.cons, parseConsItem(it))
		} else {
			ct.columns = append(ct.columns, parseColumn(it))
		}
	}
	return ct
}

func parseCreateIndex(toks []tok) *createIndex {
	c := &cur{t: toks}
	c.takeWord("create")
	ci := &createIndex{}
	ci.unique = c.takeWord("unique")
	if c.isWord("fulltext") {
		ci.kindWord = "FULLTEXT"
		c.next()
	} else if c.isWord("spatial") {
		ci.kindWord = "SPATIAL"
		c.next()
	}
	c.takeWord("index")
	c.takeWord("concurrently")
	if c.takeWord("if") {
		c.takeWord("not")
		c.takeWord("exists")
	}
	if !c.isWord("on") && c.isName() {
		q := readQualified(c)
		if len(q) > 0 {
			id := q[len(q)-1]
			ci.name = &id
		}
	}
	c.takeWord("on")
	c.takeWord("only")
	ci.table = readQualified(c)
	if c.takeWord("using") {
		if c.peek().kind == kIdent {
			ci.method = c.next().text
		}
	}
	ci.parts, _ = readParen(c)
	rest := c.t[c.i:]
	if len(rest) > 0 && rest[0].kind == kIdent && strings.EqualFold(rest[0].text, "where") {
		ci.where = rest
	}
	return ci
}

func parseAlterTable(toks []tok) *alterTable {
	c := &cur{t: toks}
	c.takeWord("alter")
	c.takeWord("table")
	if c.takeWord("if") {
		c.takeWord("exists")
	}
	at := &alterTable{}
	at.only = c.takeWord("only")
	at.table = readQualified(c)
	at.actions = splitTopComma(c.t[c.i:])
	return at
}

func parseCreateSequence(toks []tok) *createSequence {
	c := &cur{t: toks}
	c.skipUntil("sequence")
	c.takeWord("sequence")
	if c.takeWord("if") {
		c.takeWord("not")
		c.takeWord("exists")
	}
	cs := &createSequence{}
	cs.qual = readQualified(c)
	cs.opts = c.t[c.i:]
	return cs
}

func parseAlterSequence(toks []tok) *alterSequence {
	c := &cur{t: toks}
	c.skipUntil("sequence")
	c.takeWord("sequence")
	if c.takeWord("if") {
		c.takeWord("exists")
	}
	as := &alterSequence{}
	as.seq = readQualified(c)
	if c.takeWord("owned") {
		c.takeWord("by")
		as.owned = readQualified(c)
	}
	return as
}

func parseCreateType(toks []tok) *createType {
	c := &cur{t: toks}
	c.skipUntil("type")
	c.takeWord("type")
	ct := &createType{}
	ct.qual = readQualified(c)
	if c.takeWord("as") {
		if c.takeWord("enum") {
			ct.vals, _ = readParen(c)
			ct.isEnum = true
		}
	}
	return ct
}

func parseCreateSchema(toks []tok) *createSchema {
	c := &cur{t: toks}
	c.skipUntil("schema")
	c.takeWord("schema")
	if c.takeWord("if") {
		c.takeWord("not")
		c.takeWord("exists")
	}
	cs := &createSchema{}
	if !c.isWord("authorization") && c.isName() {
		cs.name = identOf(c.next())
	}
	return cs
}

// ---------------------------------------------------------------------------
// Statement classification
// ---------------------------------------------------------------------------

func createSubtype(toks []tok) string {
	for _, t := range toks {
		if t.isPunct("(") {
			break
		}
		switch t.lower() {
		case "table":
			return "table"
		case "index":
			return "index"
		case "sequence":
			return "sequence"
		case "type":
			return "type"
		case "schema":
			return "schema"
		case "view", "materialized", "function", "procedure", "trigger",
			"database", "extension", "domain", "aggregate", "operator", "role",
			"user", "publication", "policy", "cast", "rule", "server",
			"tablespace", "language", "collation":
			return "drop"
		}
	}
	return "drop"
}

func classifyKind(toks []tok) string {
	if len(toks) == 0 {
		return "drop"
	}
	switch toks[0].lower() {
	case "create":
		switch createSubtype(toks) {
		case "table":
			return "create_table"
		case "index":
			return "create_index"
		case "sequence":
			return "create_sequence"
		case "type":
			return "create_type"
		case "schema":
			return "create_schema"
		}
	case "alter":
		if len(toks) > 1 {
			switch toks[1].lower() {
			case "table":
				return "alter_table"
			case "sequence":
				return "alter_sequence"
			}
		}
	}
	return "drop"
}

func wordOrSym(t tok) string {
	if t.kind == kIdent || t.kind == kQIdent {
		return t.text
	}
	if t.kind == kPunct {
		return t.text
	}
	return "?"
}

func dropLabel(toks []tok) string {
	if len(toks) == 0 {
		return "OTHER"
	}
	first := strings.ToUpper(wordOrSym(toks[0]))
	if (first == "CREATE" || first == "ALTER" || first == "DROP") && len(toks) > 1 {
		return first + " " + strings.ToUpper(wordOrSym(toks[1]))
	}
	return first
}

// ---------------------------------------------------------------------------
// Output builder with simple spacing rules
// ---------------------------------------------------------------------------

type sw struct {
	b         strings.Builder
	prev      string
	prevLower string
}

func needSpace(prev, prevLower, cur string) bool {
	switch cur {
	case ",", ")", ";", "::", "=":
		return false
	}
	switch prev {
	case "(", "::", "=":
		return false
	}
	if cur == "(" {
		if isTypeOrFunc(prevLower) {
			return false
		}
		return true
	}
	return true
}

func (w *sw) add(s string) {
	if s == "" {
		return
	}
	if w.b.Len() > 0 && needSpace(w.prev, w.prevLower, s) {
		w.b.WriteByte(' ')
	}
	w.b.WriteString(s)
	w.prev = s
	w.prevLower = strings.ToLower(s)
}

func (w *sw) addRaw(s string) {
	if s == "" {
		return
	}
	w.b.WriteString(s)
	w.prev = s
	w.prevLower = strings.ToLower(s)
}

func (w *sw) String() string { return w.b.String() }

func renderPlain(t tok) string {
	switch t.kind {
	case kQIdent:
		return identOf(t).render(t.text)
	default:
		return t.text
	}
}

// ---------------------------------------------------------------------------
// The obfuscator
// ---------------------------------------------------------------------------

type Ob struct {
	opt Options

	tableMap map[string]string
	tableN   int

	colMap   map[string]string
	colCount map[string]int
	colSeq   map[string]int

	idxMap map[string]string
	idxN   int

	consMap                     map[string]string
	fkN, pkN, uqN, chkN, conN int

	seqMap map[string]string
	seqN   int

	typeMap map[string]string
	typeN   int

	schemaMap map[string]string
	schemaN   int

	rep Report
}

func newOb(opt Options) *Ob {
	return &Ob{
		opt:       opt,
		tableMap:  map[string]string{},
		colMap:    map[string]string{},
		colCount:  map[string]int{},
		colSeq:    map[string]int{},
		idxMap:    map[string]string{},
		consMap:   map[string]string{},
		seqMap:    map[string]string{},
		typeMap:   map[string]string{},
		schemaMap: map[string]string{},
		rep:       Report{Dropped: map[string]int{}},
	}
}

func (o *Ob) assignTable(orig string) string {
	if v, ok := o.tableMap[orig]; ok {
		return v
	}
	o.tableN++
	v := "table" + strconv.Itoa(o.tableN)
	o.tableMap[orig] = v
	o.rep.Tables++
	return v
}

func (o *Ob) typePrefix(toks []tok) string {
	if len(toks) == 0 {
		return "col"
	}
	first := strings.ToLower(strings.TrimSpace(textIfWord(toks[0])))
	second := ""
	if len(toks) > 1 {
		second = strings.ToLower(textIfWord(toks[1]))
	}
	if p, ok := stdTypePrefix(first, second); ok {
		return p
	}
	return "col"
}

func textIfWord(t tok) string {
	if t.kind == kIdent {
		return t.text
	}
	return ""
}

func (o *Ob) colNew(table, col, prefix string) string {
	key := table + "\x00" + col
	if v, ok := o.colMap[key]; ok {
		return v
	}
	var v string
	if o.opt.KeepID && strings.EqualFold(col, "id") {
		v = "id"
	} else {
		ck := table + "\x00#" + prefix
		o.colCount[ck]++
		v = prefix + "_column" + strconv.Itoa(o.colCount[ck])
	}
	o.colMap[key] = v
	o.rep.Columns++
	return v
}

func (o *Ob) lazyCol(table, col string) string {
	key := table + "\x00" + col
	if v, ok := o.colMap[key]; ok {
		return v
	}
	o.colSeq[table]++
	v := "column" + strconv.Itoa(o.colSeq[table])
	o.colMap[key] = v
	o.rep.Columns++
	return v
}

func (o *Ob) colRefVal(table, col string) string {
	if v, ok := o.colMap[table+"\x00"+col]; ok {
		return v
	}
	return o.lazyCol(table, col)
}

func (o *Ob) idxNew(orig string) string {
	if orig == "" {
		return ""
	}
	if v, ok := o.idxMap[orig]; ok {
		return v
	}
	o.idxN++
	v := "index" + strconv.Itoa(o.idxN)
	o.idxMap[orig] = v
	o.rep.Indexes++
	return v
}

func (o *Ob) consNew(orig, kind string) string {
	if orig == "" {
		return ""
	}
	if v, ok := o.consMap[orig]; ok {
		return v
	}
	var v string
	switch kind {
	case "fk":
		o.fkN++
		v = "fk" + strconv.Itoa(o.fkN)
	case "pk":
		o.pkN++
		v = "pk" + strconv.Itoa(o.pkN)
	case "uq":
		o.uqN++
		v = "uq" + strconv.Itoa(o.uqN)
	case "chk":
		o.chkN++
		v = "chk" + strconv.Itoa(o.chkN)
	default:
		o.conN++
		v = "constraint" + strconv.Itoa(o.conN)
	}
	o.consMap[orig] = v
	o.rep.Constraints++
	return v
}

func (o *Ob) seqNew(orig string) string {
	if v, ok := o.seqMap[orig]; ok {
		return v
	}
	o.seqN++
	v := "seq" + strconv.Itoa(o.seqN)
	o.seqMap[orig] = v
	o.rep.Sequences++
	return v
}

func (o *Ob) typeNew(orig string) string {
	if v, ok := o.typeMap[orig]; ok {
		return v
	}
	o.typeN++
	v := "type" + strconv.Itoa(o.typeN)
	o.typeMap[orig] = v
	o.rep.Types++
	return v
}

func (o *Ob) schemaNew(orig string) string {
	if isWellKnown(strings.ToLower(orig)) {
		return orig
	}
	if v, ok := o.schemaMap[orig]; ok {
		return v
	}
	o.schemaN++
	v := "schema" + strconv.Itoa(o.schemaN)
	o.schemaMap[orig] = v
	o.rep.Schemas++
	return v
}

func (o *Ob) renderQual(parts []ident, last func(string) string) string {
	if len(parts) == 0 {
		return ""
	}
	var out []string
	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		out = append(out, p.render(o.schemaNew(p.val)))
	}
	lp := parts[len(parts)-1]
	out = append(out, lp.render(last(lp.val)))
	return strings.Join(out, ".")
}

func (o *Ob) renderTableRef(parts []ident) string { return o.renderQual(parts, o.assignTable) }
func (o *Ob) renderSeqRef(parts []ident) string   { return o.renderQual(parts, o.seqNew) }
func (o *Ob) renderTypeRef(parts []ident) string  { return o.renderQual(parts, o.typeNew) }

func (o *Ob) renameSeqQualified(s string) string {
	parts := parseDotted(s)
	if len(parts) == 0 {
		return s
	}
	var out []string
	for i := 0; i < len(parts)-1; i++ {
		out = append(out, parts[i].render(o.schemaNew(parts[i].val)))
	}
	lp := parts[len(parts)-1]
	out = append(out, lp.render(o.seqNew(lp.val)))
	return strings.Join(out, ".")
}

func parseDotted(s string) []ident {
	var parts []ident
	i, n := 0, len(s)
	for i < n {
		if s[i] == '"' {
			j := i + 1
			var b strings.Builder
			for j < n {
				if s[j] == '"' {
					if j+1 < n && s[j+1] == '"' {
						b.WriteByte('"')
						j += 2
						continue
					}
					j++
					break
				}
				b.WriteByte(s[j])
				j++
			}
			parts = append(parts, ident{quote: '"', val: b.String()})
			i = j
			if i < n && s[i] == '.' {
				i++
			}
		} else {
			j := i
			for j < n && s[j] != '.' {
				j++
			}
			parts = append(parts, ident{val: s[i:j]})
			i = j
			if i < n && s[i] == '.' {
				i++
			}
		}
	}
	return parts
}

// ---------------------------------------------------------------------------
// Generic token rendering
// ---------------------------------------------------------------------------

func (o *Ob) skipFKActions(c *cur) {
	for !c.eof() {
		if c.peek().kind == kIdent && fkActionSet[c.peek().lower()] {
			c.next()
		} else {
			break
		}
	}
}

func (o *Ob) renderFKActionsInto(w *sw, c *cur) {
	for !c.eof() {
		t := c.next()
		if t.kind == kIdent && isFlagKeyword(strings.ToLower(t.text)) {
			w.add(strings.ToUpper(t.text))
		} else {
			w.add(renderPlain(t))
		}
	}
}

func (o *Ob) renderNextvalInto(w *sw, inner []tok) {
	for idx, t := range inner {
		if t.kind == kString {
			content := unquoteSQLString(t.text)
			w.addRaw("'" + o.renameSeqQualified(content) + "'")
			for _, rt := range inner[idx+1:] {
				if rt.kind == kIdent && isFlagKeyword(strings.ToLower(rt.text)) {
					w.add(strings.ToUpper(rt.text))
				} else {
					w.add(renderPlain(rt))
				}
			}
			return
		}
	}
	for _, t := range inner {
		w.add(renderPlain(t))
	}
}

func (o *Ob) renderRestInto(w *sw, toks []tok, table string) {
	c := &cur{t: toks}
	for !c.eof() {
		t := c.peek()
		lo := t.lower()

		if t.kind == kIdent && lo == "comment" {
			c.next()
			if !c.eof() && c.peek().kind == kString {
				c.next()
			}
			continue
		}
		if t.kind == kIdent && (lo == "enum" || lo == "set") && c.at(1).isPunct("(") {
			w.add(t.text)
			c.next()
			inner, _ := readParen(c)
			w.add("(")
			vc := 0
			for pi, p := range splitTopComma(inner) {
				if pi > 0 {
					w.add(",")
				}
				for _, pt := range p {
					if pt.kind == kString {
						vc++
						w.add("'value" + strconv.Itoa(vc) + "'")
					} else {
						w.add(renderPlain(pt))
					}
				}
			}
			w.add(")")
			continue
		}
		if t.kind == kIdent && lo == "references" {
			c.next()
			if o.opt.RemoveFK {
				readQualified(c)
				if c.isPunct("(") {
					readParen(c)
				}
				o.skipFKActions(c)
				continue
			}
			w.add("REFERENCES")
			tq := readQualified(c)
			w.add(o.renderTableRef(tq))
			if c.isPunct("(") {
				inner, _ := readParen(c)
				w.add("(")
				o.renderColListInto(w, inner, lastVal(tq))
				w.add(")")
			}
			o.renderFKActionsInto(w, c)
			continue
		}
		if t.kind == kIdent && lo == "nextval" && c.at(1).isPunct("(") {
			w.add("nextval")
			c.next()
			inner, _ := readParen(c)
			w.add("(")
			o.renderNextvalInto(w, inner)
			w.add(")")
			continue
		}
		if t.kind == kIdent && lo == "default" {
			w.add("DEFAULT")
			c.next()
			if !c.eof() && c.peek().kind == kString {
				w.add("''")
				c.next()
			}
			continue
		}
		if t.kind == kIdent {
			if nv, ok := o.typeMap[t.text]; ok {
				w.add(nv)
				c.next()
				continue
			}
			if table != "" {
				if nv, ok := o.colMap[table+"\x00"+t.text]; ok && !isFlagKeyword(lo) && !isTypeWord(lo) {
					w.add(identOf(t).render(nv))
					c.next()
					continue
				}
			}
			if isFlagKeyword(lo) {
				w.add(strings.ToUpper(t.text))
				c.next()
				continue
			}
			w.add(t.text)
			c.next()
			continue
		}
		if t.kind == kQIdent {
			if table != "" {
				if nv, ok := o.colMap[table+"\x00"+t.text]; ok {
					w.add(identOf(t).render(nv))
					c.next()
					continue
				}
			}
			w.add(identOf(t).render(t.text))
			c.next()
			continue
		}
		if t.kind == kString {
			w.add("''")
			c.next()
			continue
		}
		w.add(renderPlain(t))
		c.next()
	}
}

func (o *Ob) renderRest(toks []tok, table string) string {
	var w sw
	o.renderRestInto(&w, toks, table)
	return w.String()
}

func (o *Ob) renderExpr(toks []tok, table string) string { return o.renderRest(toks, table) }

func (o *Ob) renderColListInto(w *sw, inner []tok, table string) {
	for pi, p := range splitTopComma(inner) {
		if pi > 0 {
			w.add(",")
		}
		if len(p) == 0 {
			continue
		}
		first := p[0]
		w.add(identOf(first).render(o.colRefVal(table, first.text)))
		rest := p[1:]
		if len(rest) > 0 {
			rs := renderToksGeneric(rest)
			if rest[0].isPunct("(") {
				w.addRaw(rs)
			} else {
				w.add(rs)
			}
		}
	}
}

func renderToksGeneric(toks []tok) string {
	var w sw
	for _, t := range toks {
		if t.kind == kIdent && isFlagKeyword(strings.ToLower(t.text)) {
			w.add(strings.ToUpper(t.text))
		} else {
			w.add(renderPlain(t))
		}
	}
	return w.String()
}

func (o *Ob) renderCols(inner []tok, table string) string {
	var w sw
	o.renderColListInto(&w, inner, table)
	return w.String()
}

func (o *Ob) renderCons(cs *consItem, table string) string {
	cn := func(kind string) string {
		if cs.constraintName != nil {
			return "CONSTRAINT " + cs.constraintName.render(o.consNew(cs.constraintName.val, kind)) + " "
		}
		return ""
	}
	switch cs.kind {
	case "PRIMARY":
		return cn("pk") + "PRIMARY KEY (" + o.renderCols(cs.cols, table) + ")"
	case "UNIQUE":
		if cs.constraintName != nil {
			return cn("uq") + "UNIQUE (" + o.renderCols(cs.cols, table) + ")"
		}
		s := "UNIQUE"
		if cs.word != "" {
			s += " " + strings.ToUpper(cs.word)
		}
		if cs.name != nil {
			s += " " + cs.name.render(o.idxNew(cs.name.val))
		}
		return s + " (" + o.renderCols(cs.cols, table) + ")"
	case "INDEX":
		s := strings.ToUpper(cs.word)
		if cs.name != nil {
			s += " " + cs.name.render(o.idxNew(cs.name.val))
		}
		return s + " (" + o.renderCols(cs.cols, table) + ")"
	case "FULLTEXT", "SPATIAL":
		s := cs.kind
		if cs.word != "" {
			s += " " + strings.ToUpper(cs.word)
		} else {
			s += " KEY"
		}
		if cs.name != nil {
			s += " " + cs.name.render(o.idxNew(cs.name.val))
		}
		return s + " (" + o.renderCols(cs.cols, table) + ")"
	case "FOREIGN":
		s := cn("fk") + "FOREIGN KEY (" + o.renderCols(cs.cols, table) + ") REFERENCES " +
			o.renderTableRef(cs.refTable) + " (" + o.renderCols(cs.refCols, lastVal(cs.refTable)) + ")"
		if len(cs.actionToks) > 0 {
			if a := o.renderExpr(cs.actionToks, ""); a != "" {
				s += " " + a
			}
		}
		return s
	case "CHECK":
		return cn("chk") + "CHECK (" + o.renderExpr(cs.exprToks, table) + ")"
	default:
		return o.renderExpr(cs.exprToks, table)
	}
}

// ---------------------------------------------------------------------------
// Statement renderers
// ---------------------------------------------------------------------------

func (o *Ob) renderTail(toks []tok) string {
	var w sw
	c := &cur{t: toks}
	for !c.eof() {
		t := c.peek()
		if t.kind == kIdent && strings.EqualFold(t.text, "comment") {
			c.next()
			c.takePunct("=")
			if !c.eof() && c.peek().kind == kString {
				c.next()
			}
			continue
		}
		if t.kind == kIdent && isFlagKeyword(strings.ToLower(t.text)) {
			w.add(strings.ToUpper(t.text))
		} else {
			w.add(renderPlain(t))
		}
		c.next()
	}
	return w.String()
}

func (o *Ob) renderCreateTable(ct *createTable) string {
	if ct == nil || len(ct.qual) == 0 {
		return ""
	}
	table := lastVal(ct.qual)
	var lines []string
	for _, col := range ct.columns {
		nv := o.colMap[table+"\x00"+col.name.val]
		if nv == "" {
			nv = o.colNew(table, col.name.val, o.typePrefix(col.typeToks))
		}
		line := "  " + col.name.render(nv)
		if rest := o.renderRest(col.typeToks, table); strings.TrimSpace(rest) != "" {
			line += " " + rest
		}
		lines = append(lines, line)
	}
	for _, cs := range ct.cons {
		if o.opt.RemoveFK && cs.isFK() {
			continue
		}
		lines = append(lines, "  "+o.renderCons(cs, table))
	}
	var b strings.Builder
	b.WriteString("CREATE TABLE " + o.renderTableRef(ct.qual) + " (\n")
	b.WriteString(strings.Join(lines, ",\n"))
	b.WriteString("\n)")
	if tail := o.renderTail(ct.tail); tail != "" {
		b.WriteString(" " + tail)
	}
	b.WriteString(";")
	return b.String()
}

func (o *Ob) renderIndexParts(parts []tok, table string) string {
	var out []string
	for _, p := range splitTopComma(parts) {
		if len(p) == 0 {
			continue
		}
		first := p[0]
		if first.kind == kIdent || first.kind == kQIdent {
			if _, ok := o.colMap[table+"\x00"+first.text]; ok {
				out = append(out, o.renderCols(p, table))
				continue
			}
		}
		out = append(out, o.renderExpr(p, table))
	}
	return strings.Join(out, ", ")
}

func (o *Ob) renderCreateIndex(ci *createIndex) string {
	if ci == nil || len(ci.table) == 0 {
		return ""
	}
	table := lastVal(ci.table)
	var b strings.Builder
	b.WriteString("CREATE ")
	if ci.unique {
		b.WriteString("UNIQUE ")
	}
	if ci.kindWord != "" {
		b.WriteString(ci.kindWord + " ")
	}
	b.WriteString("INDEX ")
	if ci.name != nil {
		b.WriteString(ci.name.render(o.idxNew(ci.name.val)) + " ")
	}
	b.WriteString("ON " + o.renderTableRef(ci.table))
	if ci.method != "" {
		b.WriteString(" USING " + ci.method)
	}
	b.WriteString(" (" + o.renderIndexParts(ci.parts, table) + ")")
	if len(ci.where) > 0 {
		if wr := o.renderExpr(ci.where, table); wr != "" {
			b.WriteString(" " + wr)
		}
	}
	b.WriteString(";")
	return b.String()
}

func (o *Ob) renderAlterAction(a []tok, table string) string {
	c := &cur{t: a}
	if c.takeWord("add") {
		rest := c.t[c.i:]
		lo0 := ""
		if len(rest) > 0 {
			lo0 = rest[0].lower()
		}
		if lo0 == "column" || !isConstraintLead(lo0) {
			rc := &cur{t: rest}
			rc.takeWord("column")
			if rc.eof() {
				return ""
			}
			colTok := rc.next()
			coltyp := rc.t[rc.i:]
			nv := o.colNew(table, colTok.text, o.typePrefix(coltyp))
			s := "ADD COLUMN " + identOf(colTok).render(nv)
			if rs := o.renderRest(coltyp, table); strings.TrimSpace(rs) != "" {
				s += " " + rs
			}
			return s
		}
		cs := parseConsItem(rest)
		if o.opt.RemoveFK && cs.isFK() {
			return ""
		}
		return "ADD " + o.renderCons(cs, table)
	}
	if c.takeWord("alter") {
		c.takeWord("column")
		if c.eof() {
			return ""
		}
		colTok := c.next()
		nv := o.colRefVal(table, colTok.text)
		rest := c.t[c.i:]
		if len(rest) == 0 {
			return ""
		}
		return "ALTER COLUMN " + identOf(colTok).render(nv) + " " + o.renderRest(rest, table)
	}
	if c.takeWord("validate") {
		if c.takeWord("constraint") && c.isName() {
			id := identOf(c.next())
			return "VALIDATE CONSTRAINT " + id.render(o.consNew(id.val, "constraint"))
		}
		return ""
	}
	return ""
}

func (o *Ob) renderAlterTable(at *alterTable) string {
	if at == nil || len(at.table) == 0 {
		return ""
	}
	tableRef := o.renderTableRef(at.table)
	table := lastVal(at.table)
	var acts []string
	for _, a := range at.actions {
		if s := o.renderAlterAction(a, table); strings.TrimSpace(s) != "" {
			acts = append(acts, s)
		}
	}
	if len(acts) == 0 {
		return ""
	}
	only := ""
	if at.only {
		only = "ONLY "
	}
	if len(acts) == 1 {
		return "ALTER TABLE " + only + tableRef + " " + acts[0] + ";"
	}
	return "ALTER TABLE " + only + tableRef + "\n  " + strings.Join(acts, ",\n  ") + ";"
}

func (o *Ob) renderCreateSequence(cs *createSequence) string {
	if cs == nil || len(cs.qual) == 0 {
		return ""
	}
	s := "CREATE SEQUENCE " + o.renderSeqRef(cs.qual)
	if len(cs.opts) > 0 {
		if os := o.renderExpr(cs.opts, ""); strings.TrimSpace(os) != "" {
			s += " " + os
		}
	}
	return s + ";"
}

func (o *Ob) renderAlterSequence(as *alterSequence) string {
	if as == nil || len(as.seq) == 0 || len(as.owned) < 2 {
		return ""
	}
	col := as.owned[len(as.owned)-1]
	tableParts := as.owned[:len(as.owned)-1]
	tableOrig := lastVal(tableParts)
	colv := o.colRefVal(tableOrig, col.val)
	return "ALTER SEQUENCE " + o.renderSeqRef(as.seq) + " OWNED BY " +
		o.renderTableRef(tableParts) + "." + col.render(colv) + ";"
}

func (o *Ob) renderCreateType(ct *createType) string {
	if ct == nil || len(ct.qual) == 0 || !ct.isEnum {
		return ""
	}
	vc := 0
	var vals []string
	for _, p := range splitTopComma(ct.vals) {
		for _, pt := range p {
			if pt.kind == kString {
				vc++
				vals = append(vals, "'value"+strconv.Itoa(vc)+"'")
			}
		}
	}
	return "CREATE TYPE " + o.renderTypeRef(ct.qual) + " AS ENUM (" + strings.Join(vals, ", ") + ");"
}

func (o *Ob) renderCreateSchema(cs *createSchema) string {
	if cs == nil || cs.name.val == "" {
		return ""
	}
	return "CREATE SCHEMA " + cs.name.render(o.schemaNew(cs.name.val)) + ";"
}

// ---------------------------------------------------------------------------
// Pass 1 registration
// ---------------------------------------------------------------------------

func (o *Ob) registerTable(ct *createTable) {
	if ct == nil || len(ct.qual) == 0 {
		return
	}
	table := lastVal(ct.qual)
	o.assignTable(table)
	for _, col := range ct.columns {
		o.colNew(table, col.name.val, o.typePrefix(col.typeToks))
	}
}

func (o *Ob) registerSeq(cs *createSequence) {
	if cs == nil || len(cs.qual) == 0 {
		return
	}
	o.seqNew(lastVal(cs.qual))
}

func (o *Ob) registerType(ct *createType) {
	if ct == nil || len(ct.qual) == 0 {
		return
	}
	o.typeNew(lastVal(ct.qual))
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

func (o *Ob) Process(sql string) string {
	sql = stripCopyBlocks(sql)
	stmts := splitStatements(sql)
	mysqlQuotes := o.opt.Dialect == "mysql"

	type ps struct {
		kind string
		toks []tok
	}
	parsed := make([]ps, 0, len(stmts))
	for _, s := range stmts {
		toks := tokenize(s, mysqlQuotes)
		if len(toks) == 0 {
			continue
		}
		parsed = append(parsed, ps{classifyKind(toks), toks})
	}

	// Pass 1: register names tables/columns/sequences/types depend on.
	for _, p := range parsed {
		switch p.kind {
		case "create_table":
			o.registerTable(parseCreateTable(p.toks))
		case "create_sequence":
			o.registerSeq(parseCreateSequence(p.toks))
		case "create_type":
			o.registerType(parseCreateType(p.toks))
		}
	}

	// Pass 2: render.
	var out []string
	for _, p := range parsed {
		var r string
		switch p.kind {
		case "create_table":
			r = o.renderCreateTable(parseCreateTable(p.toks))
		case "create_index":
			r = o.renderCreateIndex(parseCreateIndex(p.toks))
		case "alter_table":
			r = o.renderAlterTable(parseAlterTable(p.toks))
		case "create_sequence":
			r = o.renderCreateSequence(parseCreateSequence(p.toks))
		case "alter_sequence":
			r = o.renderAlterSequence(parseAlterSequence(p.toks))
		case "create_type":
			r = o.renderCreateType(parseCreateType(p.toks))
		case "create_schema":
			r = o.renderCreateSchema(parseCreateSchema(p.toks))
		default:
			o.rep.Dropped[dropLabel(p.toks)]++
		}
		if strings.TrimSpace(r) != "" {
			out = append(out, r)
		}
	}
	return strings.Join(out, "\n\n")
}

// ---------------------------------------------------------------------------
// CLI & HTTP server
// ---------------------------------------------------------------------------

func normDialect(d string) string {
	switch strings.ToLower(d) {
	case "postgres", "postgresql", "pg", "psql":
		return "postgres"
	case "mysql", "mariadb":
		return "mysql"
	default:
		return "auto"
	}
}

func isPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func fprintReport(w io.Writer, r Report) {
	fmt.Fprintln(w, "-- obfuscation report")
	fmt.Fprintf(w, "-- renamed: tables=%d columns=%d indexes=%d constraints=%d sequences=%d types=%d schemas=%d\n",
		r.Tables, r.Columns, r.Indexes, r.Constraints, r.Sequences, r.Types, r.Schemas)
	if len(r.Dropped) > 0 {
		keys := make([]string, 0, len(r.Dropped))
		for k := range r.Dropped {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintln(w, "-- dropped statements (not transformable / data):")
		for _, k := range keys {
			fmt.Fprintf(w, "--   %s x%d\n", k, r.Dropped[k])
		}
	}
}

type apiRequest struct {
	SQL      string `json:"sql"`
	Dialect  string `json:"dialect"`
	RemoveFK bool   `json:"removeFk"`
	KeepID   bool   `json:"keepId"`
}

type apiResponse struct {
	Output string `json:"output"`
	Report Report `json:"report"`
}

func noStore(h http.Header) {
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	h.Set("X-Content-Type-Options", "nosniff")
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
	noStore(w.Header())
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req apiRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	o := newOb(Options{RemoveFK: req.RemoveFK, KeepID: req.KeepID, Dialect: normDialect(req.Dialect)})
	resp := apiResponse{Output: o.Process(req.SQL), Report: o.rep}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func runServer(addr string) {
	indexHTML, err := assets.ReadFile("index.html")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: missing embedded index.html:", err)
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		noStore(w.Header())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	mux.HandleFunc("/api/obfuscate", apiHandler)

	fmt.Printf("redact.sql v%s -> http://%s\n", version, addr)
	fmt.Println("All processing is local and in memory. Nothing is sent or stored externally.")
	fmt.Println("Press Ctrl+C to stop.")
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

func main() {
	serve := flag.Bool("serve", false, "force web server mode")
	addr := flag.String("addr", "127.0.0.1:8585", "web server listen address")
	out := flag.String("o", "", "write output to file (default: stdout)")
	removeFK := flag.Bool("remove-fk", false, "remove all foreign key constraints")
	keepID := flag.Bool("keep-id", true, "preserve columns literally named \"id\"")
	dialect := flag.String("dialect", "auto", "auto | mysql | postgres")
	quiet := flag.Bool("quiet", false, "suppress the report on stderr (CLI mode)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "redact.sql v%s — SQL schema obfuscator\n\n", version)
		fmt.Fprintf(os.Stderr, "Web UI:  %s                  # then open http://127.0.0.1:8585\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "CLI:     cat dump.sql | %s -o clean.sql\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("redactsql v%s\n", version)
		return
	}

	piped := isPiped()
	if *serve || (!piped && *out == "" && flag.NArg() == 0) {
		runServer(*addr)
		return
	}

	var data []byte
	var err error
	if flag.NArg() > 0 {
		data, err = os.ReadFile(flag.Arg(0))
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	o := newOb(Options{RemoveFK: *removeFK, KeepID: *keepID, Dialect: normDialect(*dialect)})
	res := o.Process(string(data))

	if *out != "" {
		if err := os.WriteFile(*out, []byte(res+"\n"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	} else {
		fmt.Println(res)
	}
	if !*quiet {
		fprintReport(os.Stderr, o.rep)
	}
}
