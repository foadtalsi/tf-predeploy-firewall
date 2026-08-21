// L'extracteur ForceNew, comme module à part.
//
// Il est en Go et il le reste : ce qu'il lit est du source Go, et le seul
// analyseur qui fasse autorité pour du Go est celui de Go. Le porter en
// Python voudrait dire écrire un parseur de Go, ce qui remplacerait une
// dépendance à un toolchain par une dépendance à une réimplémentation.
//
// Module séparé plutôt qu'un dossier du scanner : `pip install` ne doit
// jamais avoir besoin d'un compilateur Go. Seul le workflow hebdomadaire qui
// régénère les packs construit ce binaire.
module github.com/foadtalsi/tf-predeploy-firewall/tools/forcenew-extractor

go 1.23
