resource "aws_db_instance" "primary" {
  identifier          = "prod-primary"
  engine              = "postgres"
  engine_version      = "16.4"
  instance_class      = "db.r6g.xlarge"
  allocated_storage   = 100
  db_name             = "appdb"
  username            = "appuser"
  password            = data.aws_secretsmanager_secret_version.db.secret_string
  storage_encrypted   = true
  deletion_protection = true
  skip_final_snapshot = false
}

data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/db/password"
}
