// Read Terraform provider Go source and write a JSON ForceNew index.
// Terraform's schema JSON omits replacement metadata, so extraction uses provider declarations.
//
// From this directory:
//
//	go run . --provider aws --provider-src /tmp/provider-src \
//	  --provider-version 5.70.0 --out /tmp/aws_forcenew.json
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		provider   = flag.String("provider", "aws", "provider name (aws, azurerm); selects the extractor and labels the index")
		sourcePath = flag.String("provider-src", "", "provider source checkout path (required)")
		version    = flag.String("provider-version", "", "provider version recorded in the index")
		outputPath = flag.String("out", "", "output JSON path (required)")
	)
	flag.Parse()

	if *sourcePath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "forcenew-extractor: --provider-src and --out are required")
		flag.Usage()
		os.Exit(2)
	}

	index, err := extractorFor(*provider)(*sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forcenew-extractor: %v\n", err)
		os.Exit(1)
	}
	if err := writeForceNewIndex(*outputPath, *provider, *version, index); err != nil {
		fmt.Fprintf(os.Stderr, "forcenew-extractor: %v\n", err)
		os.Exit(1)
	}

	// Print resolution rates for pack-refresh review. A sudden drop can indicate unsupported
	// provider source changes.
	fmt.Printf("wrote %s (SDKv2 %d/%d resolved, Framework %d/%d resolved, %d resource types)\n",
		*outputPath, index.SDKResourcesResolved, index.SDKResourcesSeen,
		index.FrameworkResolved, index.FrameworkSeen, len(index.TopLevel)+len(index.Nested))
}
