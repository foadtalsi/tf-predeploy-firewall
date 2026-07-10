package rules

import "github.com/foadtalsi/tf-predeploy-firewall/internal/parser"

// ChangedAttrKey identifies one attribute inside the PR's own .tf diff,
// either top-level ("engine") or inside a nested block
// ("root_block_device.volume_type"). Used by plan-based rules to tell
// whether a value the plan says changed was actually touched by this PR,
// versus having drifted from some other source (console edits, another
// pipeline, a provider default shifting).
type ChangedAttrKey string

// changedAttrsForResource returns the set of attribute keys whose literal
// value differs between base and head, or whose presence changed
// (added/removed). Non-literal expressions (var.x, data.foo.bar) are
// treated conservatively as "changed" — we can't prove they didn't, so we'd
// rather under-report drift than over-report it.
func changedAttrsForResource(head, base *parser.Resource) map[ChangedAttrKey]bool {
	changed := map[ChangedAttrKey]bool{}
	if head == nil || base == nil {
		return changed
	}

	diffAttrMaps(head.Attributes, base.Attributes, "", changed)

	blockByType := func(blocks []*parser.NestedBlock) map[string]*parser.NestedBlock {
		m := map[string]*parser.NestedBlock{}
		for _, b := range blocks {
			m[b.Type] = b
		}
		return m
	}
	headBlocks := blockByType(head.Blocks)
	baseBlocks := blockByType(base.Blocks)
	for blockType, headBlk := range headBlocks {
		baseBlk, ok := baseBlocks[blockType]
		if !ok {
			continue // whole block is new; not a per-attribute drift comparison
		}
		diffAttrMaps(headBlk.Attributes, baseBlk.Attributes, blockType+".", changed)
	}

	return changed
}

func diffAttrMaps(head, base map[string]*parser.Attribute, prefix string, out map[ChangedAttrKey]bool) {
	for name, headAttr := range head {
		baseAttr, existed := base[name]
		if !existed {
			out[ChangedAttrKey(prefix+name)] = true
			continue
		}
		if !headAttr.IsLiteral || !baseAttr.IsLiteral || headAttr.RawValue != baseAttr.RawValue {
			out[ChangedAttrKey(prefix+name)] = true
		}
	}
	for name := range base {
		if _, stillPresent := head[name]; !stillPresent {
			out[ChangedAttrKey(prefix+name)] = true
		}
	}
}
