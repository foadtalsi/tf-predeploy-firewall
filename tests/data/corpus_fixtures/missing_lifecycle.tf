resource "aws_db_instance" "unprotected" {
  identifier     = "prod-db-2"
  engine         = "postgres"
  username       = "admin"
  instance_class = "db.t3.medium"
}

resource "aws_db_instance" "protected" {
  identifier     = "prod-db-3"
  engine         = "postgres"
  username       = "admin"
  instance_class = "db.t3.medium"

  lifecycle {
    prevent_destroy = true
  }
}
