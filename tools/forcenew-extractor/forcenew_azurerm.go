package main

import (
	"fmt"
	"go/ast"
	"os"
	"path/filepath"
)

// ForceNew extraction for terraform-provider-azurerm.
//
// The AWS extractor keys on `@SDKResource("aws_x")` doc annotations, which
// are an AWS-provider convention. azurerm names its resources two other
// ways, both structural rather than comment-based:
//
//   - Untyped (pluginsdk, wrapping SDKv2): each service package's
//     registration.go returns a literal
//     `map[string]*pluginsdk.Resource{"azurerm_x": resourceX()}` — the map
//     entry is the only place the resource type string and its schema
//     function meet.
//   - Typed (internal/sdk): a resource is a struct whose
//     `ResourceType() string` method returns "azurerm_x" and whose
//     `Arguments() map[string]*pluginsdk.Schema` method returns the schema.
//
// The schema literals themselves are SDKv2 shapes under another package
// name, so once a (type, schema-map) pair is found, the shared
// walkSDKSchemaMap does the rest — pluginsdk.Schema carries the same
// `ForceNew: true` field, and isSchemaSelector accepts both package names.
func extractForceNewAzurerm(srcRoot string) (*forceNewIndex, error) {
	serviceRoot := filepath.Join(srcRoot, "internal", "services")
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
			fmt.Fprintf(os.Stderr, "genpack: skipping %s: %v\n", e.Name(), err)
			continue
		}
		collectAzurermUntyped(pkg, idx)
		collectAzurermTyped(pkg, idx)
	}
	return idx, nil
}

// collectAzurermUntyped finds every `"azurerm_x": resourceX()` entry in a
// package's pluginsdk.Resource registration maps and walks the schema each
// named function returns.
func collectAzurermUntyped(pkg *packageIndex, idx *forceNewIndex) {
	for _, f := range pkg.files {
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			mt, ok := cl.Type.(*ast.MapType)
			if !ok {
				return true
			}
			// map[string]*pluginsdk.Resource — the registration shape.
			if key, ok := mt.Key.(*ast.Ident); !ok || key.Name != "string" {
				return true
			}
			if !isSchemaSelector(mt.Value, "Resource") {
				return true
			}

			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				rType, ok := basicString(kv.Key)
				if !ok {
					continue
				}
				call, ok := kv.Value.(*ast.CallExpr)
				if !ok {
					continue
				}
				fnName, ok := call.Fun.(*ast.Ident)
				if !ok {
					continue
				}
				fn, ok := pkg.funcs[fnName.Name]
				if !ok {
					continue
				}

				idx.SDKResourcesSeen++
				schemaMap := resolveSDKSchemaMap(fn, pkg)
				if schemaMap == nil {
					continue
				}
				idx.SDKResourcesResolved++
				walkSDKSchemaMap(schemaMap, "", rType, pkg, nil, idx)
			}
			return true
		})
	}
}

// collectAzurermTyped pairs each receiver type's ResourceType() string with
// its Arguments() schema map.
func collectAzurermTyped(pkg *packageIndex, idx *forceNewIndex) {
	for recv, methods := range pkg.methods {
		rtMethod, ok := methods["ResourceType"]
		if !ok {
			continue
		}
		rType := returnedString(rtMethod)
		if rType == "" {
			continue
		}
		_ = recv

		args, ok := methods["Arguments"]
		if !ok {
			// A typed data source has ResourceType but no Arguments —
			// nothing with ForceNew semantics to extract.
			continue
		}

		idx.FrameworkSeen++
		schemaMap := findSchemaMapLit(args)
		if schemaMap == nil {
			continue
		}
		idx.FrameworkResolved++
		walkSDKSchemaMap(schemaMap, "", rType, pkg, nil, idx)
	}
}

// returnedString extracts the string a niladic method returns, for
// `func (r XResource) ResourceType() string { return "azurerm_x" }`.
// Anything more dynamic returns "" and the resource is counted as a gap.
func returnedString(fn *ast.FuncDecl) string {
	if fn.Body == nil {
		return ""
	}
	var out string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) != 1 || out != "" {
			return true
		}
		if s, ok := basicString(ret.Results[0]); ok {
			out = s
		}
		return true
	})
	return out
}
