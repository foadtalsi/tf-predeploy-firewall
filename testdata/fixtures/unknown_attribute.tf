# INVALID ON PURPOSE. This is the only fixture that is.
#
# `enable_quantum_io` is not an argument of aws_instance, and is not an
# argument of anything — it is the unknown-attribute rule's entire test case.
# Terraform, tflint and your editor's language server all flag it, and they
# are all correct to. Removing it does not fix a defect, it deletes the test:
# TestFixtures_AreValidTerraform fails if the scanner ever stops reporting
# this file.
#
# .vscode/settings.json keeps the Terraform language server out of testdata
# for this reason — a corpus is not infrastructure.
#
# Every other fixture passes `terraform validate` against the real provider
# schemas — see testdata/validate-fixtures.sh.

resource "aws_instance" "web" {
  ami               = "ami-0123456789abcdef0"
  instance_type     = "t3.micro"
  enable_quantum_io = true
}
