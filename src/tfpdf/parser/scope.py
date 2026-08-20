"""Résolution de portée : transformer `var.x` et `local.y` en les valeurs
qu'ils portent.

Port de internal/parser/scope.go.

Terraform cloisonne les locals et les variables par *répertoire*, pas par
fichier : un local déclaré dans locals.tf est visible dans rds.tf. `build_scope`
prend donc chaque fichier .tf d'un répertoire et produit un contexte
d'évaluation unique pour tous.

Ce que cela apporte : un mot de passe posé dans la valeur par défaut d'un
`variable` et lu ailleurs par `password = var.db_password` devient une
découverte sur la ligne qui le lit, au lieu d'une valeur irrésoluble que chaque
règle saute.
"""

from __future__ import annotations

from .. import hcl
from ..hcl import EvalContext, Value


def build_scope(files_by_path: dict[str, bytes]) -> EvalContext | None:
    """Rend un contexte d'évaluation pour un répertoire, à partir du contenu de
    ses fichiers .tf indexé par chemin.

    La résolution se fait en une seule passe : un local défini en fonction d'un
    autre local ne se résout que si celui dont il dépend était déjà résoluble par
    lui-même. Poursuivre les chaînes demanderait d'implémenter le graphe de
    dépendances de Terraform, pour un cas rare dans les motifs que ce scanner
    cherche.
    """
    locals_: dict[str, Value] = {}
    vars_: dict[str, Value] = {}

    for path, src in files_by_path.items():
        file, diags = hcl.parse_config(src, path)
        if diags.has_errors():
            # One unparseable file must not cost us the scope of the rest of
            # the directory; the engine reports that file's parse error itself.
            continue

        for block in file.body.blocks:
            if block.type == "locals":
                for name, attr in block.body.attributes.items():
                    v, d = attr.expr.value(None)
                    if not d.has_errors() and v.is_wholly_known():
                        locals_[name] = v
            elif block.type == "variable" and len(block.labels) == 1:
                # Only `default` is a value we can know statically. A variable
                # without one is supplied at plan time, so it stays unknown.
                default = block.body.attributes.get("default")
                if default is None:
                    continue
                v, d = default.expr.value(None)
                if not d.has_errors() and v.is_wholly_known():
                    vars_[block.labels[0]] = v

    if not locals_ and not vars_:
        return None

    variables: dict[str, Value] = {}
    if locals_:
        variables["local"] = hcl.object_val(locals_)
    if vars_:
        variables["var"] = hcl.object_val(vars_)
    return EvalContext(variables)
