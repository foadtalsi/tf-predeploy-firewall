"""Une découverte sans correctif, rendue comme commentaire en ligne.

L'implémentation Go panique ici, et c'est le seul endroit où le port ne
reproduit délibérément pas le comportement de Go.

`report.ReviewCommentBody` et `report.GitLabSuggestionBody` déréférencent
`f.Fix` sans vérification de nullité — `f.Fix.Note` dans le rendu de corps
partagé, et `f.Fix.EndLine - f.Fix.StartLine` dans l'en-tête de bloc GitLab.
`Fix.Text()`, deux lignes au-dessus, *est* protégé, avec un
`if f == nil { return "" }` explicite : l'intention était donc clairement qu'un
correctif absent se rende comme une suggestion vide plutôt que de planter ; la
garde manque simplement aux deux autres lectures.

C'est latent, pas actif : le `postSuggestions` de cmd/tf-predeploy-firewall
écarte `f.Fix == nil` avant d'appeler l'un ou l'autre rendu, et c'est le seul
appelant en production. Rien n'est cassé aujourd'hui.

Porter la panique voudrait dire écrire une vérification dont le seul but serait
de lever — et un plantage dans le code qui poste les commentaires de PR emporte
avec lui le commentaire de synthèse, chez tout futur appelant qui oublierait la
garde. Le Python rend donc la suggestion vide que le `Text()` protégé implique
déjà, et ce test épingle ce choix pour qu'il se lise comme une décision et non
comme un oubli.
"""

from __future__ import annotations

from tfpdf.report import (
    Category,
    Finding,
    Severity,
    fix_marker,
    gitlab_suggestion_body,
    review_comment_body,
)


def _no_fix() -> Finding:
    return Finding(
        file="s3.tf",
        line=3,
        category=Category.PUBLIC_EXPOSURE,
        severity=Severity.HIGH,
        resource="aws_s3_bucket.logs",
        message="bucket is public",
    )


def test_review_comment_body_renders_an_empty_suggestion_rather_than_crashing() -> None:
    body = review_comment_body(_no_fix())
    assert "```suggestion\n```\n" in body
    assert "bucket is public" in body


def test_gitlab_suggestion_body_treats_a_missing_fix_as_a_single_line() -> None:
    assert "```suggestion:-0+0\n" in gitlab_suggestion_body(_no_fix())


def test_fix_marker_is_still_stable_without_a_fix() -> None:
    """Le marqueur hache le texte du correctif, qui est "" ici. Il doit rester
    calculable, et rester différent entre deux découvertes différentes."""
    a = _no_fix()
    b = _no_fix()
    b.resource = "aws_s3_bucket.other"
    assert fix_marker(a) == fix_marker(_no_fix())
    assert fix_marker(a) != fix_marker(b)
