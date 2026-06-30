resource "aws_db_instance" "unprotected" {
  identifier = "prod-db-2"
  engine     = "postgres"
  username   = "admin"
}

resource "aws_db_instance" "protected" {
  identifier = "prod-db-3"
  engine     = "postgres"
  username   = "admin"

  lifecycle {
    prevent_destroy = true
  }
}
