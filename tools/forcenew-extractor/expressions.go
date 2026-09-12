package main

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
)

func annotatedResourceType(function *ast.FuncDecl, re *regexp.Regexp) string {
	if function.Doc == nil {
		return ""
	}
	for _, c := range function.Doc.List {
		if m := re.FindStringSubmatch(c.Text); m != nil {
			return m[1]
		}
	}
	return ""
}

// resolveString turns a schema key into its literal value, following the
// package's own constants and the provider-wide `names` package.
func resolveString(expression ast.Expr, servicePackage *packageIndex, providerConstants map[string]string) (string, bool) {
	switch v := expression.(type) {
	case *ast.BasicLit:
		return basicString(v)
	case *ast.Ident:
		if s, ok := servicePackage.consts[v.Name]; ok {
			return s, true
		}
	case *ast.SelectorExpr:
		if x, ok := v.X.(*ast.Ident); ok && x.Name == "names" {
			if s, ok := providerConstants[v.Sel.Name]; ok {
				return s, true
			}
		}
	}
	return "", false
}

func basicString(expression ast.Expr) (string, bool) {
	literal, ok := expression.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

// asStructLit unwraps an optional leading `&` from a composite literal.
func asStructLit(expression ast.Expr) *ast.CompositeLit {
	switch v := expression.(type) {
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			literal, _ := v.X.(*ast.CompositeLit)
			return literal
		}
	case *ast.CompositeLit:
		return v
	}
	return nil
}

// asMapLit returns expr as a map composite literal, if it is one.
func asMapLit(expression ast.Expr) *ast.CompositeLit {
	literal := asStructLit(expression)
	if literal == nil {
		return nil
	}
	if _, ok := literal.Type.(*ast.MapType); !ok {
		return nil
	}
	return literal
}

func isSchemaMapType(expression ast.Expr) bool {
	mt, ok := expression.(*ast.MapType)
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
func isSchemaSelector(expression ast.Expr, typeName string) bool {
	return isSelectorType(expression, "schema", typeName) || isSelectorType(expression, "pluginsdk", typeName)
}

// isSelectorType reports whether expr is the type `pkg.name`, ignoring a
// leading pointer.
func isSelectorType(expression ast.Expr, pkgName, typeName string) bool {
	if star, ok := expression.(*ast.StarExpr); ok {
		expression = star.X
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	x, ok := selector.X.(*ast.Ident)
	if !ok {
		return false
	}
	return x.Name == pkgName && selector.Sel.Name == typeName
}
