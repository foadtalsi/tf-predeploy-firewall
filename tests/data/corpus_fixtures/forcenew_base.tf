resource "aws_db_instance" "primary" {
  identifier     = "prod-db"
  engine         = "postgres"
  username       = "admin"
  instance_class = "db.t3.medium"
}
