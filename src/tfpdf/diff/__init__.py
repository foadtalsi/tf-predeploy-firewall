"""Read changed Terraform files and their previous contents from a local Git checkout."""

from .git import (
    ChangedFile,
    GitError,
    all_terraform_files,
    all_terragrunt_files,
    changed_terraform_files,
    changed_terragrunt_files,
    remote_url,
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
    "remote_url",
    "show_file",
    "staged_terraform_files",
    "staged_terragrunt_files",
    "staged_tfvars_files",
    "uncommitted_terraform_files",
    "uncommitted_terragrunt_files",
    "uncommitted_tfvars_files",
]
