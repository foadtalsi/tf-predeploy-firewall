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
func extractForceNewAzurerm(sourceRoot string) (*forceNewIndex, error) {
	serviceRoot := filepath.Join(sourceRoot, "internal", "services")
	entries, err := os.ReadDir(serviceRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", serviceRoot, err)
	}

	index := newForceNewIndex()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		servicePackage, err := parsePackage(filepath.Join(serviceRoot, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "forcenew-extractor: skipping %s: %v\n", e.Name(), err)
			continue
		}
		collectAzurermUntyped(servicePackage, index)
		collectAzurermTyped(servicePackage, index)
	}
	return index, nil
}

// collectAzurermUntyped finds every `"azurerm_x": resourceX()` entry in a
// package's pluginsdk.Resource registration maps and walks the schema each
// named function returns.
func collectAzurermUntyped(servicePackage *packageIndex, index *forceNewIndex) {
	for _, f := range servicePackage.files {
		ast.Inspect(f, func(n ast.Node) bool {
			literal, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			mt, ok := literal.Type.(*ast.MapType)
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

			for _, element := range literal.Elts {
				entry, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				resourceType, ok := basicString(entry.Key)
				if !ok {
					continue
				}
				call, ok := entry.Value.(*ast.CallExpr)
				if !ok {
					continue
				}
				functionName, ok := call.Fun.(*ast.Ident)
				if !ok {
					continue
				}
				function, ok := servicePackage.funcs[functionName.Name]
				if !ok {
					continue
				}

				index.SDKResourcesSeen++
				schemaMap := resolveSDKSchemaMap(function, servicePackage)
				if schemaMap == nil {
					continue
				}
				index.SDKResourcesResolved++
				walkSDKSchemaMap(schemaMap, "", resourceType, servicePackage, nil, index)
			}
			return true
		})
	}
}

// collectAzurermTyped pairs each receiver type's ResourceType() string with
// its Arguments() schema map.
func collectAzurermTyped(servicePackage *packageIndex, index *forceNewIndex) {
	for receiverType, methods := range servicePackage.methods {
		resourceTypeMethod, ok := methods["ResourceType"]
		if !ok {
			continue
		}
		resourceType := returnedString(resourceTypeMethod)
		if resourceType == "" {
			continue
		}
		_ = receiverType

		args, ok := methods["Arguments"]
		if !ok {
			// A typed data source has ResourceType but no Arguments —
			// nothing with ForceNew semantics to extract.
			continue
		}

		index.FrameworkSeen++
		schemaMap := findSchemaMapLit(args)
		if schemaMap == nil {
			continue
		}
		index.FrameworkResolved++
		walkSDKSchemaMap(schemaMap, "", resourceType, servicePackage, nil, index)
	}
}

// returnedString extracts the string a niladic method returns, for
// `func (r XResource) ResourceType() string { return "azurerm_x" }`.
// Anything more dynamic returns "" and the resource is counted as a gap.
func returnedString(function *ast.FuncDecl) string {
	if function.Body == nil {
		return ""
	}
	var out string
	ast.Inspect(function.Body, func(n ast.Node) bool {
		returnStatement, ok := n.(*ast.ReturnStmt)
		if !ok || len(returnStatement.Results) != 1 || out != "" {
			return true
		}
		if s, ok := basicString(returnStatement.Results[0]); ok {
			out = s
		}
		return true
	})
	return out
}
