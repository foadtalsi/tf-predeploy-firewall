package planjson

import (
	"encoding/json"
	"fmt"
	"os"
)

// Load reads and parses a `terraform show -json` plan file from disk.
func Load(path string) (*PlanFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading plan JSON %s: %w", path, err)
	}
	var pf PlanFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("parsing plan JSON %s: %w (expected output of `terraform show -json <planfile>`)", path, err)
	}
	return &pf, nil
}
