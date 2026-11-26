resource "google_sql_database_instance" "main" {
  name             = "prod-pg"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
  }
}
