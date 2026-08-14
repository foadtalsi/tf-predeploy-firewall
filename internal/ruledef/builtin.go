package ruledef

import (
	_ "embed"
	"fmt"
	"sync"
)

//go:embed rules.yaml
var builtinYAML []byte

var (
	builtinOnce sync.Once
	builtin     *Pack
	builtinErr  error
)

// Builtin returns the rule pack compiled into the binary.
//
// Parsed once and shared: the pack is immutable after loading, and every
// scanned file would otherwise recompile the same regexes.
func Builtin() (*Pack, error) {
	builtinOnce.Do(func() {
		builtin, builtinErr = Load(builtinYAML)
		if builtinErr != nil {
			builtinErr = fmt.Errorf("the embedded rule pack is invalid: %w", builtinErr)
		}
	})
	return builtin, builtinErr
}

// BuiltinYAML returns the raw embedded pack, for tooling that wants to show
// or copy it — `--rules-dry-run`, and anyone starting their own pack from
// the built-in one rather than from a blank file.
func BuiltinYAML() []byte {
	out := make([]byte, len(builtinYAML))
	copy(out, builtinYAML)
	return out
}
