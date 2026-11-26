resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = "europe-west1"

  template {
    containers {
      image = "europe-docker.pkg.dev/acme-prod/api/api:1.4.2"

      env {
        name = "DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = "db-password"
            version = "latest"
          }
        }
      }
    }
  }
}
