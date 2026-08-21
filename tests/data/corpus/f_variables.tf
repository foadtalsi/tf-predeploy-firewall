variable "with_default" { default = "resolved-me" }
variable "no_default" { type = string }
variable "obj_default" {
  default = { password = "nested-secret", port = 5432 }
}
variable "list_default" { default = ["a", "b"] }
resource "aws_db_instance" "uses_vars" {
  password    = var.with_default
  unresolved  = var.no_default
  from_obj    = var.obj_default.password
  from_local  = local.n
  from_list   = var.list_default[1]
  interpolated = "prefix-${var.with_default}"
  computed    = "${var.with_default}-${local.s}"
}
