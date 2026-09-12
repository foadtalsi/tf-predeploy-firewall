package main

import (
	"go/ast"
	"strings"
)

func collectFrameworkResources(servicePackage *packageIndex, providerConstants map[string]string, index *forceNewIndex) {
	for _, function := range servicePackage.funcs {
		resourceType := annotatedResourceType(function, frameworkResourceRe)
		if resourceType == "" {
			continue
		}
		index.FrameworkSeen++

		typeName := frameworkReceiverType(function)
		if typeName == "" {
			continue
		}
		method, ok := servicePackage.methods[typeName]["Schema"]
		if !ok || method.Body == nil {
			continue
		}
		schemaLit := frameworkSchemaLit(method)
		if schemaLit == nil {
			continue
		}
		index.FrameworkResolved++
		walkFrameworkBlock(schemaLit, "", resourceType, servicePackage, providerConstants, index)
	}
}

// frameworkReceiverType finds the struct a `newResourceFoo` constructor
// returns, so we can locate its Schema method.
func frameworkReceiverType(function *ast.FuncDecl) string {
	var name string
	ast.Inspect(function, func(n ast.Node) bool {
		if name != "" {
			return false
		}
		literal, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if identifier, ok := literal.Type.(*ast.Ident); ok {
			name = identifier.Name
			return false
		}
		return true
	})
	return name
}

// frameworkSchemaLit finds `resp.Schema = schema.Schema{...}`.
func frameworkSchemaLit(function *ast.FuncDecl) *ast.CompositeLit {
	var result *ast.CompositeLit
	ast.Inspect(function.Body, func(n ast.Node) bool {
		if result != nil {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, rhs := range assign.Rhs {
			literal := asStructLit(rhs)
			if literal != nil && isSelectorType(literal.Type, "schema", "Schema") {
				result = literal
				return false
			}
		}
		return true
	})
	return result
}

// walkFrameworkBlock handles the Attributes/Blocks pair that appears both on
// a schema.Schema and on every NestedBlockObject/NestedAttributeObject.
func walkFrameworkBlock(block *ast.CompositeLit, path, resourceType string, servicePackage *packageIndex, providerConstants map[string]string, index *forceNewIndex) {
	if strings.Count(path, ".") > 8 {
		return
	}

	for _, element := range block.Elts {
		entry, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, _ := entry.Key.(*ast.Ident)
		if key == nil || (key.Name != "Attributes" && key.Name != "Blocks") {
			continue
		}
		m := asMapLit(entry.Value)
		if m == nil {
			continue
		}
		for _, e := range m.Elts {
			ekv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			name, ok := resolveString(ekv.Key, servicePackage, providerConstants)
			if !ok {
				continue
			}
			body := asStructLit(ekv.Value)
			if body == nil {
				continue
			}
			if hasRequiresReplace(body) {
				index.add(resourceType, path, name)
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
				walkFrameworkBlock(nested, childPath, resourceType, servicePackage, providerConstants, index)
			}
		}
	}
}

// hasRequiresReplace reports whether an attribute/block literal carries a
// RequiresReplace plan modifier at its own level — deliberately not
// recursing, so a modifier on a nested attribute isn't attributed to its
// parent.
func hasRequiresReplace(lit *ast.CompositeLit) bool {
	for _, element := range lit.Elts {
		entry, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		identifier, _ := entry.Key.(*ast.Ident)
		if identifier == nil || identifier.Name != "PlanModifiers" {
			continue
		}
		list, ok := entry.Value.(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, item := range list.Elts {
			call, ok := item.(*ast.CallExpr)
			if !ok {
				continue
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if strings.HasPrefix(selector.Sel.Name, "RequiresReplace") {
				return true
			}
		}
	}
	return false
}
