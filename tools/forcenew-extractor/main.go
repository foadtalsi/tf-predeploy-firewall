// Lit le source Go d'un fournisseur Terraform et écrit l'index ForceNew.
//
// Ce que cet outil produit : un fichier JSON qui dit, pour chaque type de
// ressource, quels arguments détruisent et recréent la ressource quand on les
// change. C'est ce que `tfpdf-genpack` consomme ensuite pour bâtir les packs.
//
// Pourquoi il existe : `terraform providers schema -json` n'expose pas
// ForceNew. Le schéma sur le fil dit qu'un argument est optionnel ou calculé,
// jamais que le modifier remplace la ressource — et c'est exactement le fait
// que ce scanner existe pour signaler. La seule source qui fasse autorité est
// la déclaration de schéma du fournisseur, en Go.
//
// Il était auparavant un sous-commande de `genpack`, dans l'arbre Go du
// scanner, et le workflow le tirait du module publié. Ce n'était pas tenable :
// cet outil est une pièce permanente de la chaîne des packs, pas un
// échafaudage de portage, et il dépendait d'une étiquette de version d'un
// arbre destiné à disparaître.
//
//	go run ./tools/forcenew-extractor \
//	  --provider aws \
//	  --provider-src /tmp/provider-src \
//	  --provider-version 5.70.0 \
//	  --out /tmp/aws_forcenew.json
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		provider   = flag.String("provider", "aws", "nom court du fournisseur (aws, azurerm) — choisit l'extracteur et est enregistré dans l'index")
		sourcePath = flag.String("provider-src", "", "chemin d'un checkout du source du fournisseur (obligatoire)")
		version    = flag.String("provider-version", "", "version du fournisseur que cet index décrit, enregistrée dedans")
		outputPath = flag.String("out", "", "chemin du fichier JSON à écrire (obligatoire)")
	)
	flag.Parse()

	if *sourcePath == "" || *outputPath == "" {
		fmt.Fprintln(os.Stderr, "forcenew-extractor: --provider-src et --out sont obligatoires")
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

	// Les taux de résolution vont sur stdout parce que le workflow les colle
	// dans le corps de la PR. Une chute brutale veut presque toujours dire que
	// le fournisseur a restructuré son source et que l'extracteur ne reconnaît
	// plus ses déclarations — pas que la donnée a changé.
	fmt.Printf("wrote %s (SDKv2 %d/%d resolved, Framework %d/%d resolved, %d resource types)\n",
		*outputPath, index.SDKResourcesResolved, index.SDKResourcesSeen,
		index.FrameworkResolved, index.FrameworkSeen, len(index.TopLevel)+len(index.Nested))
}
