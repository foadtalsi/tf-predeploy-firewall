package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// This file recovers ForceNew information from the AWS provider's Go source.
//
// It has to: `terraform providers schema -json` does not expose ForceNew at
// all. The wire schema says an argument is optional/computed, never that
// changing it destroys and recreates the resource — which is precisely the
// fact this scanner exists to warn about. The only authoritative source is
// the provider's own schema declarations, so we read those.
//
// Two declaration styles are covered, because the provider is mid-migration:
//   - SDKv2:     schema.Schema{ ForceNew: true }                  (~73% of resources)
//   - Framework: PlanModifiers: []planmodifier.X{ ...RequiresReplace() }
//
// Anything this can't resolve statically (a schema assembled by a helper, a
// map built in a loop) is simply skipped. A missing ForceNew entry costs a
// missed warning; a wrong one costs a blocked PR, so we never guess.

var (
	sdkResourceRe       = regexp.MustCompile(`@SDKResource\("([a-z0-9_]+)"`)
	frameworkResourceRe = regexp.MustCompile(`@FrameworkResource\("([a-z0-9_]+)"`)
)

// forceNewIndex is the extraction result: resource type -> ForceNew paths.
type forceNewIndex struct {
	// TopLevel maps resource type -> ForceNew top-level argument names.
	TopLevel map[string][]string
	// Nested maps resource type -> dotted block path -> ForceNew names.
	Nested map[string]map[string][]string

	// Stats, reported so pack coverage is a measured number rather than a
	// claim.
	SDKResourcesSeen     int
	SDKResourcesResolved int
	FrameworkSeen        int
	FrameworkResolved    int
}

func newForceNewIndex() *forceNewIndex {
	return &forceNewIndex{
		TopLevel: map[string][]string{},
		Nested:   map[string]map[string][]string{},
	}
}

func (idx *forceNewIndex) add(rType, path, attr string) {
	if path == "" {
		idx.TopLevel[rType] = append(idx.TopLevel[rType], attr)
		return
	}
	if idx.Nested[rType] == nil {
		idx.Nested[rType] = map[string][]string{}
	}
	idx.Nested[rType][path] = append(idx.Nested[rType][path], attr)
}

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

// extractForceNew walks every service package under <src>/internal/service.
func extractForceNew(srcRoot string) (*forceNewIndex, error) {
	namesConsts, err := loadStringConsts(filepath.Join(srcRoot, "names"))
	if err != nil {
		return nil, fmt.Errorf("loading names constants: %w", err)
	}

	serviceRoot := filepath.Join(srcRoot, "internal", "service")
	entries, err := os.ReadDir(serviceRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", serviceRoot, err)
	}

	idx := newForceNewIndex()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pkg, err := parsePackage(filepath.Join(serviceRoot, e.Name()))
		if err != nil {
			// A package we can't parse is a gap in coverage, not a reason to
			// abandon the other 270.
			fmt.Fprintf(os.Stderr, "genpack: skipping %s: %v\n", e.Name(), err)
			continue
		}
		collectSDKResources(pkg, namesConsts, idx)
		collectFrameworkResources(pkg, namesConsts, idx)
	}
	return idx, nil
}

func parsePackage(dir string) (*packageIndex, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	pkg := &packageIndex{
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
		pkg.files = append(pkg.files, f)

		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil || len(d.Recv.List) == 0 {
					pkg.funcs[d.Name.Name] = d
					continue
				}
				recv := receiverTypeName(d.Recv.List[0].Type)
				if recv == "" {
					continue
				}
				if pkg.methods[recv] == nil {
					pkg.methods[recv] = map[string]*ast.FuncDecl{}
				}
				pkg.methods[recv][d.Name.Name] = d
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
								pkg.consts[ident.Name] = s
							}
							continue
						}
						// Several resources keep their schema in a package-level
						// var and hand a copy to schema.Resource
						// (`Schema: maps.Clone(queueSchema)`), so the map literal
						// has to be reachable by name too.
						if m := asMapLit(vs.Values[i]); m != nil && isSchemaMapType(m.Type) {
							pkg.vars[ident.Name] = m
						}
					}
				}
			}
		}
	}
	return pkg, nil
}

// loadStringConsts reads package-level `X = "y"` constants from a directory,
// used for the provider's shared `names` package: schema keys are very often
// written as names.AttrARN rather than "arn".
func loadStringConsts(dir string) (map[string]string, error) {
	pkg, err := parsePackage(dir)
	if err != nil {
		return nil, err
	}
	return pkg.consts, nil
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr: // generic receiver
		return receiverTypeName(t.X)
	}
	return ""
}

// ---------------------------------------------------------------------------
// SDKv2: schema.Schema{ ForceNew: true }
// ---------------------------------------------------------------------------

func collectSDKResources(pkg *packageIndex, namesConsts map[string]string, idx *forceNewIndex) {
	for _, fn := range pkg.funcs {
		rType := annotatedResourceType(fn, sdkResourceRe)
		if rType == "" {
			continue
		}
		idx.SDKResourcesSeen++

		schemaMap := resolveSDKSchemaMap(fn, pkg)
		if schemaMap == nil {
			continue
		}
		idx.SDKResourcesResolved++
		walkSDKSchemaMap(schemaMap, "", rType, pkg, namesConsts, idx)
	}
}

func annotatedResourceType(fn *ast.FuncDecl, re *regexp.Regexp) string {
	if fn.Doc == nil {
		return ""
	}
	for _, c := range fn.Doc.List {
		if m := re.FindStringSubmatch(c.Text); m != nil {
			return m[1]
		}
	}
	return ""
}

// resolveSDKSchemaMap finds the map[string]*schema.Schema for a resource,
// whether it's written inline as `Schema:` or indirected through
// `SchemaFunc:` (the style the provider is converging on).
func resolveSDKSchemaMap(fn *ast.FuncDecl, pkg *packageIndex) *ast.CompositeLit {
	var result *ast.CompositeLit

	ast.Inspect(fn, func(n ast.Node) bool {
		if result != nil {
			return false
		}
		cl, ok := n.(*ast.CompositeLit)
		if !ok || !isSchemaSelector(cl.Type, "Resource") {
			return true
		}
		for _, elt := range cl.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, _ := kv.Key.(*ast.Ident)
			if key == nil {
				continue
			}
			switch key.Name {
			case "Schema":
				if m := resolveSchemaMapExpr(kv.Value, pkg); m != nil {
					result = m
					return false
				}
			case "SchemaFunc":
				if m := schemaFromFuncRef(kv.Value, pkg); m != nil {
					result = m
					return false
				}
			}
		}
		return true
	})
	return result
}

// resolveSchemaMapExpr resolves the value of a `Schema:` field to the map
// literal behind it, following the indirections the provider actually uses:
// an inline literal, a package-level var, or a wrapper call such as
// `maps.Clone(queueSchema)`.
func resolveSchemaMapExpr(expr ast.Expr, pkg *packageIndex) *ast.CompositeLit {
	switch v := expr.(type) {
	case *ast.CompositeLit, *ast.UnaryExpr:
		return asMapLit(expr)
	case *ast.Ident:
		if m, ok := pkg.vars[v.Name]; ok {
			return m
		}
		if fn, ok := pkg.funcs[v.Name]; ok {
			return findSchemaMapLit(fn)
		}
	case *ast.CallExpr:
		// `Schema: resourceFooSchema()` — the map lives in the called
		// function. This must be tried before the argument unwrap below:
		// a niladic call has no arguments, and falling through used to let
		// the caller's ast.Inspect keep walking into some nested block's
		// resource literal and mistake ITS schema map for the top level —
		// silently wrong ForceNew data, not just missing data.
		if fnName, ok := v.Fun.(*ast.Ident); ok {
			if fn, ok := pkg.funcs[fnName.Name]; ok {
				if m := findSchemaMapLit(fn); m != nil {
					return m
				}
			}
		}
		// Unwrap one level of wrapping (maps.Clone, mergeSchemas, ...) by
		// resolving the first argument that yields a schema map.
		for _, arg := range v.Args {
			if m := resolveSchemaMapExpr(arg, pkg); m != nil {
				return m
			}
		}
	}
	return nil
}

// schemaFromFuncRef resolves `SchemaFunc: resourceFooSchema` (or an inline
// func literal) to the map literal it returns.
func schemaFromFuncRef(expr ast.Expr, pkg *packageIndex) *ast.CompositeLit {
	switch v := expr.(type) {
	case *ast.Ident:
		target, ok := pkg.funcs[v.Name]
		if !ok {
			return nil
		}
		return findSchemaMapLit(target)
	case *ast.FuncLit:
		return findSchemaMapLitNode(v)
	}
	return nil
}

func findSchemaMapLit(fn *ast.FuncDecl) *ast.CompositeLit {
	if fn.Body == nil {
		return nil
	}
	return findSchemaMapLitNode(fn.Body)
}

// findSchemaMapLitNode looks for a map[string]*schema.Schema literal,
// preferring one that is actually returned over any incidental one.
func findSchemaMapLitNode(n ast.Node) *ast.CompositeLit {
	var returned, any *ast.CompositeLit

	ast.Inspect(n, func(node ast.Node) bool {
		switch t := node.(type) {
		case *ast.ReturnStmt:
			for _, r := range t.Results {
				if m := asMapLit(r); m != nil && returned == nil {
					returned = m
				}
			}
		case *ast.CompositeLit:
			if isSchemaMapType(t.Type) && any == nil {
				any = t
			}
		}
		return true
	})

	if returned != nil {
		return returned
	}
	return any
}

// walkSDKSchemaMap records ForceNew arguments, recursing into nested
// `Elem: &schema.Resource{Schema: ...}` blocks so a path like
// "root_block_device.volume_type" is reported the same way the attribute
// surface names it.
func walkSDKSchemaMap(m *ast.CompositeLit, path, rType string, pkg *packageIndex, namesConsts map[string]string, idx *forceNewIndex) {
	// Guard against a pathological or cyclic schema definition.
	if strings.Count(path, ".") > 8 {
		return
	}

	for _, elt := range m.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		attrName, ok := resolveString(kv.Key, pkg, namesConsts)
		if !ok {
			continue
		}
		body := asStructLit(kv.Value)
		if body == nil {
			continue
		}

		for _, f := range body.Elts {
			fkv, ok := f.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			fname, _ := fkv.Key.(*ast.Ident)
			if fname == nil {
				continue
			}
			switch fname.Name {
			case "ForceNew":
				if id, ok := fkv.Value.(*ast.Ident); ok && id.Name == "true" {
					idx.add(rType, path, attrName)
				}
			case "Elem":
				nested := nestedResourceSchema(fkv.Value)
				if nested == nil {
					continue
				}
				childPath := attrName
				if path != "" {
					childPath = path + "." + attrName
				}
				walkSDKSchemaMap(nested, childPath, rType, pkg, namesConsts, idx)
			}
		}
	}
}

// nestedResourceSchema pulls the inner map out of
// `Elem: &schema.Resource{ Schema: map[string]*schema.Schema{...} }`.
// An `Elem: &schema.Schema{...}` (a list of primitives) has no nested
// arguments and returns nil.
func nestedResourceSchema(expr ast.Expr) *ast.CompositeLit {
	cl := asStructLit(expr)
	if cl == nil || !isSchemaSelector(cl.Type, "Resource") {
		return nil
	}
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "Schema" {
			return asMapLit(kv.Value)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Plugin Framework: PlanModifiers: []planmodifier.X{ ...RequiresReplace() }
// ---------------------------------------------------------------------------

func collectFrameworkResources(pkg *packageIndex, namesConsts map[string]string, idx *forceNewIndex) {
	for _, fn := range pkg.funcs {
		rType := annotatedResourceType(fn, frameworkResourceRe)
		if rType == "" {
			continue
		}
		idx.FrameworkSeen++

		typeName := frameworkReceiverType(fn)
		if typeName == "" {
			continue
		}
		method, ok := pkg.methods[typeName]["Schema"]
		if !ok || method.Body == nil {
			continue
		}
		schemaLit := frameworkSchemaLit(method)
		if schemaLit == nil {
			continue
		}
		idx.FrameworkResolved++
		walkFrameworkBlock(schemaLit, "", rType, pkg, namesConsts, idx)
	}
}

// frameworkReceiverType finds the struct a `newResourceFoo` constructor
// returns, so we can locate its Schema method.
func frameworkReceiverType(fn *ast.FuncDecl) string {
	var name string
	ast.Inspect(fn, func(n ast.Node) bool {
		if name != "" {
			return false
		}
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if id, ok := cl.Type.(*ast.Ident); ok {
			name = id.Name
			return false
		}
		return true
	})
	return name
}

// frameworkSchemaLit finds `resp.Schema = schema.Schema{...}`.
func frameworkSchemaLit(fn *ast.FuncDecl) *ast.CompositeLit {
	var result *ast.CompositeLit
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if result != nil {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, rhs := range assign.Rhs {
			cl := asStructLit(rhs)
			if cl != nil && isSelectorType(cl.Type, "schema", "Schema") {
				result = cl
				return false
			}
		}
		return true
	})
	return result
}

// walkFrameworkBlock handles the Attributes/Blocks pair that appears both on
// a schema.Schema and on every NestedBlockObject/NestedAttributeObject.
func walkFrameworkBlock(block *ast.CompositeLit, path, rType string, pkg *packageIndex, namesConsts map[string]string, idx *forceNewIndex) {
	if strings.Count(path, ".") > 8 {
		return
	}

	for _, elt := range block.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, _ := kv.Key.(*ast.Ident)
		if key == nil || (key.Name != "Attributes" && key.Name != "Blocks") {
			continue
		}
		m := asMapLit(kv.Value)
		if m == nil {
			continue
		}
		for _, e := range m.Elts {
			ekv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			name, ok := resolveString(ekv.Key, pkg, namesConsts)
			if !ok {
				continue
			}
			body := asStructLit(ekv.Value)
			if body == nil {
				continue
			}
			if hasRequiresReplace(body) {
				idx.add(rType, path, name)
			}
			// Recurse through NestedObject into deeper attributes/blocks.
			for _, f := range body.Elts {
				fkv, ok := f.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				fid, _ := fkv.Key.(*ast.Ident)
				if fid == nil || fid.Name != "NestedObject" {
					continue
				}
				nested := asStructLit(fkv.Value)
				if nested == nil {
					continue
				}
				childPath := name
				if path != "" {
					childPath = path + "." + name
				}
				walkFrameworkBlock(nested, childPath, rType, pkg, namesConsts, idx)
			}
		}
	}
}

// hasRequiresReplace reports whether an attribute/block literal carries a
// RequiresReplace plan modifier at its own level — deliberately not
// recursing, so a modifier on a nested attribute isn't attributed to its
// parent.
func hasRequiresReplace(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		id, _ := kv.Key.(*ast.Ident)
		if id == nil || id.Name != "PlanModifiers" {
			continue
		}
		list, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, item := range list.Elts {
			call, ok := item.(*ast.CallExpr)
			if !ok {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if strings.HasPrefix(sel.Sel.Name, "RequiresReplace") {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Small AST helpers
// ---------------------------------------------------------------------------

// resolveString turns a schema key into its literal value, following the
// package's own constants and the provider-wide `names` package.
func resolveString(expr ast.Expr, pkg *packageIndex, namesConsts map[string]string) (string, bool) {
	switch v := expr.(type) {
	case *ast.BasicLit:
		return basicString(v)
	case *ast.Ident:
		if s, ok := pkg.consts[v.Name]; ok {
			return s, true
		}
	case *ast.SelectorExpr:
		if x, ok := v.X.(*ast.Ident); ok && x.Name == "names" {
			if s, ok := namesConsts[v.Sel.Name]; ok {
				return s, true
			}
		}
	}
	return "", false
}

func basicString(expr ast.Expr) (string, bool) {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// asStructLit unwraps an optional leading `&` from a composite literal.
func asStructLit(expr ast.Expr) *ast.CompositeLit {
	switch v := expr.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			cl, _ := v.X.(*ast.CompositeLit)
			return cl
		}
	case *ast.CompositeLit:
		return v
	}
	return nil
}

// asMapLit returns expr as a map composite literal, if it is one.
func asMapLit(expr ast.Expr) *ast.CompositeLit {
	cl := asStructLit(expr)
	if cl == nil {
		return nil
	}
	if _, ok := cl.Type.(*ast.MapType); !ok {
		return nil
	}
	return cl
}

func isSchemaMapType(expr ast.Expr) bool {
	mt, ok := expr.(*ast.MapType)
	if !ok {
		return false
	}
	key, ok := mt.Key.(*ast.Ident)
	if !ok || key.Name != "string" {
		return false
	}
	val := mt.Value
	if star, ok := val.(*ast.StarExpr); ok {
		val = star.X
	}
	return isSchemaSelector(val, "Schema")
}

// isSchemaSelector matches `schema.<name>` and `pluginsdk.<name>` — the AWS
// provider imports SDKv2 as `schema`, azurerm wraps the same types in its
// own `pluginsdk` package with identical field names, so one matcher serves
// both providers.
func isSchemaSelector(expr ast.Expr, typeName string) bool {
	return isSelectorType(expr, "schema", typeName) || isSelectorType(expr, "pluginsdk", typeName)
}

// isSelectorType reports whether expr is the type `pkg.name`, ignoring a
// leading pointer.
func isSelectorType(expr ast.Expr, pkgName, typeName string) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return x.Name == pkgName && sel.Sel.Name == typeName
}
