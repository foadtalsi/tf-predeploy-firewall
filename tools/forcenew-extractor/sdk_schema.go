package main

import (
	"go/ast"
	"strings"
)

func collectSDKResources(servicePackage *packageIndex, providerConstants map[string]string, index *forceNewIndex) {
	for _, function := range servicePackage.funcs {
		resourceType := annotatedResourceType(function, sdkResourceRe)
		if resourceType == "" {
			continue
		}
		index.SDKResourcesSeen++

		schemaMap := resolveSDKSchemaMap(function, servicePackage)
		if schemaMap == nil {
			continue
		}
		index.SDKResourcesResolved++
		walkSDKSchemaMap(schemaMap, "", resourceType, servicePackage, providerConstants, index)
	}
}

// resolveSDKSchemaMap finds the map[string]*schema.Schema for a resource,
// whether it's written inline as `Schema:` or indirected through
// `SchemaFunc:` (the style the provider is converging on).
func resolveSDKSchemaMap(function *ast.FuncDecl, servicePackage *packageIndex) *ast.CompositeLit {
	var result *ast.CompositeLit

	ast.Inspect(function, func(n ast.Node) bool {
		if result != nil {
			return false
		}
		literal, ok := n.(*ast.CompositeLit)
		if !ok || !isSchemaSelector(literal.Type, "Resource") {
			return true
		}
		for _, element := range literal.Elts {
			entry, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, _ := entry.Key.(*ast.Ident)
			if key == nil {
				continue
			}
			switch key.Name {
			case "Schema":
				if m := resolveSchemaMapExpr(entry.Value, servicePackage); m != nil {
					result = m
					return false
				}
			case "SchemaFunc":
				if m := schemaFromFuncRef(entry.Value, servicePackage); m != nil {
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
func resolveSchemaMapExpr(expression ast.Expr, servicePackage *packageIndex) *ast.CompositeLit {
	switch v := expression.(type) {
	case *ast.CompositeLit, *ast.UnaryExpr:
		return asMapLit(expression)
	case *ast.Ident:
		if m, ok := servicePackage.vars[v.Name]; ok {
			return m
		}
		if function, ok := servicePackage.funcs[v.Name]; ok {
			return findSchemaMapLit(function)
		}
	case *ast.CallExpr:
		// `Schema: resourceFooSchema()` — the map lives in the called
		// function. This must be tried before the argument unwrap below:
		// a niladic call has no arguments, and falling through used to let
		// the caller's ast.Inspect keep walking into some nested block's
		// resource literal and mistake ITS schema map for the top level —
		// silently wrong ForceNew data, not just missing data.
		if functionName, ok := v.Fun.(*ast.Ident); ok {
			if function, ok := servicePackage.funcs[functionName.Name]; ok {
				if m := findSchemaMapLit(function); m != nil {
					return m
				}
			}
		}
		// Unwrap one level of wrapping (maps.Clone, mergeSchemas, ...) by
		// resolving the first argument that yields a schema map.
		for _, arg := range v.Args {
			if m := resolveSchemaMapExpr(arg, servicePackage); m != nil {
				return m
			}
		}
	}
	return nil
}

// schemaFromFuncRef resolves `SchemaFunc: resourceFooSchema` (or an inline
// func literal) to the map literal it returns.
func schemaFromFuncRef(expression ast.Expr, servicePackage *packageIndex) *ast.CompositeLit {
	switch v := expression.(type) {
	case *ast.Ident:
		target, ok := servicePackage.funcs[v.Name]
		if !ok {
			return nil
		}
		return findSchemaMapLit(target)
	case *ast.FuncLit:
		return findSchemaMapLitNode(v)
	}
	return nil
}

func findSchemaMapLit(function *ast.FuncDecl) *ast.CompositeLit {
	if function.Body == nil {
		return nil
	}
	return findSchemaMapLitNode(function.Body)
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
func walkSDKSchemaMap(m *ast.CompositeLit, path, resourceType string, servicePackage *packageIndex, providerConstants map[string]string, index *forceNewIndex) {
	// Guard against a pathological or cyclic schema definition.
	if strings.Count(path, ".") > 8 {
		return
	}

	for _, element := range m.Elts {
		entry, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		attrName, ok := resolveString(entry.Key, servicePackage, providerConstants)
		if !ok {
			continue
		}
		body := asStructLit(entry.Value)
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
				if identifier, ok := fkv.Value.(*ast.Ident); ok && identifier.Name == "true" {
					index.add(resourceType, path, attrName)
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
				walkSDKSchemaMap(nested, childPath, resourceType, servicePackage, providerConstants, index)
			}
		}
	}
}

// nestedResourceSchema pulls the inner map out of
// `Elem: &schema.Resource{ Schema: map[string]*schema.Schema{...} }`.
// An `Elem: &schema.Schema{...}` (a list of primitives) has no nested
// arguments and returns nil.
func nestedResourceSchema(expression ast.Expr) *ast.CompositeLit {
	literal := asStructLit(expression)
	if literal == nil || !isSchemaSelector(literal.Type, "Resource") {
		return nil
	}
	for _, element := range literal.Elts {
		entry, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if identifier, ok := entry.Key.(*ast.Ident); ok && identifier.Name == "Schema" {
			return asMapLit(entry.Value)
		}
	}
	return nil
}
