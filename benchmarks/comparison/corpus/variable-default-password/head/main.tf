resource "aws_db_instance" "primary" {
  identifier          = "prod-primary"
  engine              = "postgres"
  engine_version      = "16.4"
  instance_class      = "db.r6g.xlarge"
  allocated_storage   = 100
  db_name             = "appdb"
  username            = "appuser"
  password            = var.db_password
  storage_encrypted   = true
  deletion_protection = true
  skip_final_snapshot = false
}

resource "random_password" "db" {
  length  = 32
  special = true
}

variable "db_password" {
  type    = string
  default = "Vh3$kP8m!Qz2Ld7w"
}
