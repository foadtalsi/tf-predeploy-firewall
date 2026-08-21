// Command parserdump serialises what internal/parser produces for a set of
// .tf files, as stable JSON.
//
// It exists to generate the oracle the Python port is tested against: run it
// once over every fixture, commit the output, and the Python parser has a
// reference produced by hashicorp/hcl itself rather than by someone's reading
// of the spec. It is a build-time tool for the port, not part of the scanner.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
)

type dumpAttr struct {
	Name         string `json:"name"`
	RawValue     string `json:"raw_value"`
	IsLiteral    bool   `json:"is_literal"`
	ResolvedFrom string `json:"resolved_from"`
	StartLine    int    `json:"start_line"`
	StartCol     int    `json:"start_col"`
	StartByte    int    `json:"start_byte"`
	EndLine      int    `json:"end_line"`
	EndCol       int    `json:"end_col"`
	EndByte      int    `json:"end_byte"`
}

type dumpBlock struct {
	Type       string     `json:"type"`
	Labels     []string   `json:"labels"`
	StartLine  int        `json:"start_line"`
	Attributes []dumpAttr `json:"attributes"`
}

type dumpResource struct {
	Kind                string      `json:"kind"`
	Type                string      `json:"type"`
	Name                string      `json:"name"`
	Address             string      `json:"address"`
	File                string      `json:"file"`
	DefStartLine        int         `json:"def_start_line"`
	DefStartCol         int         `json:"def_start_col"`
	DefStartByte        int         `json:"def_start_byte"`
	DefEndLine          int         `json:"def_end_line"`
	DefEndByte          int         `json:"def_end_byte"`
	Attributes          []dumpAttr  `json:"attributes"`
	Blocks              []dumpBlock `json:"blocks"`
	HasLifecycleBlock   bool        `json:"has_lifecycle_block"`
	PreventDestroyValue *bool       `json:"prevent_destroy_value"`
	PreventDestroyLine  int         `json:"prevent_destroy_line"`
	LifecycleLine       int         `json:"lifecycle_line"`
}

type dumpFile struct {
	File      string         `json:"file"`
	ParseErr  string         `json:"parse_error"`
	Resources []dumpResource `json:"resources"`
}

func attrs(m map[string]*parser.Attribute) []dumpAttr {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]dumpAttr, 0, len(names))
	for _, n := range names {
		a := m[n]
		out = append(out, dumpAttr{
			Name:         a.Name,
			RawValue:     a.RawValue,
			IsLiteral:    a.IsLiteral,
			ResolvedFrom: a.ResolvedFrom,
			StartLine:    a.Range.Start.Line,
			StartCol:     a.Range.Start.Column,
			StartByte:    a.Range.Start.Byte,
			EndLine:      a.Range.End.Line,
			EndCol:       a.Range.End.Column,
			EndByte:      a.Range.End.Byte,
		})
	}
	return out
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: parserdump <file.tf> [more.tf ...]")
		os.Exit(2)
	}

	// Group by directory so scope resolution matches how the scanner builds
	// it: locals and variable defaults are visible across one directory.
	byDir := map[string]map[string][]byte{}
	for _, path := range os.Args[1:] {
		src, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(1)
		}
		dir := filepath.Dir(path)
		if byDir[dir] == nil {
			byDir[dir] = map[string][]byte{}
		}
		byDir[dir][path] = src
	}

	var out []dumpFile
	for _, path := range os.Args[1:] {
		dir := filepath.Dir(path)
		ctx := parser.BuildScope(byDir[dir])
		src := byDir[dir][path]

		df := dumpFile{File: filepath.Base(path), Resources: []dumpResource{}}
		resources, err := parser.ParseFileWithContext(filepath.Base(path), src, ctx)
		if err != nil {
			df.ParseErr = err.Error()
			out = append(out, df)
			continue
		}
		for _, r := range resources {
			dr := dumpResource{
				Kind:                string(r.Kind),
				Type:                r.Type,
				Name:                r.Name,
				Address:             r.Address(),
				File:                r.File,
				DefStartLine:        r.DefRange.Start.Line,
				DefStartCol:         r.DefRange.Start.Column,
				DefStartByte:        r.DefRange.Start.Byte,
				DefEndLine:          r.DefRange.End.Line,
				DefEndByte:          r.DefRange.End.Byte,
				Attributes:          attrs(r.Attributes),
				Blocks:              []dumpBlock{},
				HasLifecycleBlock:   r.HasLifecycleBlock,
				PreventDestroyValue: r.PreventDestroyValue,
				PreventDestroyLine:  r.PreventDestroyRange.Start.Line,
				LifecycleLine:       r.LifecycleRange.Start.Line,
			}
			for _, b := range r.Blocks {
				dr.Blocks = append(dr.Blocks, dumpBlock{
					Type:       b.Type,
					Labels:     b.Labels,
					StartLine:  b.Range.Start.Line,
					Attributes: attrs(b.Attributes),
				})
			}
			df.Resources = append(df.Resources, dr)
		}
		out = append(out, df)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}
