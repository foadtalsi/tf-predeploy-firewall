"""Récupération des fichiers .tf modifiés dans une PR et, là où c'est
nécessaire, de leur contenu d'avant changement — depuis un checkout git local.

Port de internal/diff. Le scanner n'a jamais besoin d'identifiants cloud ni d'un
fichier d'état terraform.
"""

from .git import (
    ChangedFile,
    GitError,
    all_terraform_files,
    all_terragrunt_files,
    changed_terraform_files,
    changed_terragrunt_files,
    show_file,
)
from .local import (
    staged_terraform_files,
    staged_terragrunt_files,
    uncommitted_terraform_files,
    uncommitted_terragrunt_files,
)
from .tfvars import (
    all_tfvars_files,
    changed_tfvars_files,
    is_tfvars,
    staged_tfvars_files,
    uncommitted_tfvars_files,
)

__all__ = [
    "ChangedFile",
    "GitError",
    "all_terraform_files",
    "all_terragrunt_files",
    "all_tfvars_files",
    "changed_terraform_files",
    "changed_terragrunt_files",
    "changed_tfvars_files",
    "is_tfvars",
    "show_file",
    "staged_terraform_files",
    "staged_terragrunt_files",
    "staged_tfvars_files",
    "uncommitted_terraform_files",
    "uncommitted_terragrunt_files",
    "uncommitted_tfvars_files",
]
