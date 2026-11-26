resource "google_container_cluster" "main" {
  name                  = "main"
  location              = "europe-west1"
  enable_autopilot_mode = true
}
