// Package planjson parses the JSON produced by `terraform show -json
// <planfile>` — phase 2 input. Unlike the phase 1 static scan, this
// requires the user's own CI job to run `terraform plan` with real cloud
// credentials; this tool never runs terraform or touches the cloud itself.
// It only reads the resulting JSON to detect risks a pure HCL diff cannot
// see: a confirmed destroy/replace, a plan touching far more resources
// than the PR's own diff, or a sensitive attribute drifting outside the
// PR's changes.
package planjson

// PlanFile is the minimal subset of the `terraform show -json` schema
// (format_version 1.x) this tool understands.
type PlanFile struct {
	FormatVersion   string           `json:"format_version"`
	ResourceChanges []ResourceChange `json:"resource_changes"`
}

// ResourceChange mirrors one entry of resource_changes[].
type ResourceChange struct {
	Address      string `json:"address"`
	ModuleAddr   string `json:"module_address"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	ProviderName string `json:"provider_name"`
	Change       Change `json:"change"`
}

// Change mirrors resource_changes[].change. Before/After are decoded as
// generic maps (numbers become float64) — good enough for equality checks,
// which is all the rules need.
type Change struct {
	Actions []string               `json:"actions"`
	Before  map[string]interface{} `json:"before"`
	After   map[string]interface{} `json:"after"`
}

// IsReplace reports whether this change destroys and recreates the resource
// (actions contain both "delete" and "create", in either order — Terraform
// emits ["delete","create"] for a "replace", vs. a create-before-destroy
// replace which emits ["create","delete"]).
func (c Change) IsReplace() bool {
	return c.hasAction("delete") && c.hasAction("create")
}

// IsDestroyOnly reports whether the resource is being deleted with no
// replacement — the single most dangerous action a plan can contain.
func (c Change) IsDestroyOnly() bool {
	return len(c.Actions) == 1 && c.Actions[0] == "delete"
}

// IsPureUpdate reports whether the change is an in-place update (no
// destroy/recreate involved).
func (c Change) IsPureUpdate() bool {
	return len(c.Actions) == 1 && c.Actions[0] == "update"
}

// IsNoOp reports whether Terraform found nothing to do for this resource.
func (c Change) IsNoOp() bool {
	return len(c.Actions) == 1 && c.Actions[0] == "no-op"
}

func (c Change) hasAction(action string) bool {
	for _, a := range c.Actions {
		if a == action {
			return true
		}
	}
	return false
}
