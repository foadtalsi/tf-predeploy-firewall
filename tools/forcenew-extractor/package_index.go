package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// packageIndex holds everything we need to resolve identifiers within one
// provider service package (functions, methods, and package-level string
// constants used as schema keys).
type packageIndex struct {
	funcs   map[string]*ast.FuncDecl            // function name -> decl
	methods map[string]map[string]*ast.FuncDecl // receiver type -> method name -> decl
	consts  map[string]string                   // const name -> string value
	vars    map[string]*ast.CompositeLit        // package-level var -> map[string]*schema.Schema literal
	files   []*ast.File
}

func parsePackage(dir string) (*packageIndex, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	servicePackage := &packageIndex{
		funcs:   map[string]*ast.FuncDecl{},
		methods: map[string]map[string]*ast.FuncDecl{},
		consts:  map[string]string{},
		vars:    map[string]*ast.CompositeLit{},
	}
	fset := token.NewFileSet()

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			continue
		}
		servicePackage.files = append(servicePackage.files, f)

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 {
					servicePackage.funcs[d.Name.Name] = d
					continue
				}
				receiverType := receiverTypeName(d.Recv.List[0].Type)
				if receiverType == "" {
					continue
				}
				if servicePackage.methods[receiverType] == nil {
					servicePackage.methods[receiverType] = map[string]*ast.FuncDecl{}
				}
				servicePackage.methods[receiverType][d.Name.Name] = d
			case *ast.GenDecl:
				if d.Tok != token.CONST && d.Tok != token.VAR {
					continue
				}
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, ident := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						if d.Tok == token.CONST {
							if s, ok := basicString(vs.Values[i]); ok {
								servicePackage.consts[ident.Name] = s
							}
							continue
						}
						// Several resources keep their schema in a package-level
						// var and hand a copy to schema.Resource
						// (`Schema: maps.Clone(queueSchema)`), so the map literal
						// has to be reachable by name too.
						if m := asMapLit(vs.Values[i]); m != nil && isSchemaMapType(m.Type) {
							servicePackage.vars[ident.Name] = m
						}
					}
				}
			}
		}
	}
	return servicePackage, nil
}

// loadStringConsts reads package-level `X = "y"` constants from a directory,
// used for the provider's shared `names` package: schema keys are very often
// written as names.AttrARN rather than "arn".
func loadStringConsts(dir string) (map[string]string, error) {
	servicePackage, err := parsePackage(dir)
	if err != nil {
		return nil, err
	}
	return servicePackage.consts, nil
}

func receiverTypeName(expression ast.Expr) string {
	switch t := expression.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver
		return receiverTypeName(t.X)
	}
	return ""
}
