# Positives: basic roles granted at project, folder or organisation level.
resource "google_project_iam_member" "owner" {
  project = "acme-prod"
  role    = "roles/owner"
  member  = "user:alice@acme.example"
}

resource "google_project_iam_member" "editor" {
  project = "acme-prod"
  role    = "roles/editor"
  member  = "serviceAccount:ci@acme-prod.iam.gserviceaccount.com"
}

resource "google_project_iam_binding" "editors" {
  project = "acme-prod"
  role    = "roles/editor"
  members = ["group:platform@acme.example"]
}

resource "google_folder_iam_member" "owner" {
  folder = "folders/123456"
  role   = "roles/owner"
  member = "group:admins@acme.example"
}

resource "google_organization_iam_binding" "owners" {
  org_id  = "123456789"
  role    = "roles/owner"
  members = ["group:admins@acme.example"]
}

data "google_iam_policy" "project_owner" {
  binding {
    role    = "roles/owner"
    members = ["user:alice@acme.example"]
  }
}

# Positives: legacy ABAC switched on.
resource "google_container_cluster" "abac" {
  name               = "web"
  location           = "europe-west1"
  enable_legacy_abac = true
}

resource "google_container_cluster" "abac_autoscaled" {
  name               = "batch"
  location           = "europe-west1"
  initial_node_count = 1
  enable_legacy_abac = true
}

resource "google_container_cluster" "abac_private" {
  name               = "internal"
  location           = "europe-west1"
  enable_legacy_abac = true

  private_cluster_config {
    enable_private_nodes = true
  }
}

resource "google_container_cluster" "abac_zonal" {
  name               = "dev"
  location           = "europe-west1-b"
  enable_legacy_abac = true
}

resource "google_container_cluster" "abac_legacy_app" {
  name               = "legacy"
  location           = "europe-west1"
  enable_legacy_abac = true
}

# Near misses.
resource "google_project_iam_member" "viewer" {
  project = "acme-prod"
  role    = "roles/viewer"
  member  = "group:auditors@acme.example"
}

resource "google_project_iam_member" "predefined" {
  project = "acme-prod"
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:app@acme-prod.iam.gserviceaccount.com"
}

resource "google_project_iam_member" "custom_role" {
  project = "acme-prod"
  role    = "projects/acme-prod/roles/deployer"
  member  = "serviceAccount:ci@acme-prod.iam.gserviceaccount.com"
}

# Bucket-level legacy roles are scoped to one bucket, not to every service.
resource "google_storage_bucket_iam_member" "legacy_owner" {
  bucket = "acme-assets"
  role   = "roles/storage.legacyBucketOwner"
  member = "group:platform@acme.example"
}

resource "google_project_iam_member" "from_variable" {
  project = "acme-prod"
  role    = var.role
  member  = "group:platform@acme.example"
}

resource "google_container_cluster" "rbac" {
  name               = "secure"
  location           = "europe-west1"
  enable_legacy_abac = false
}

resource "google_container_cluster" "default" {
  name     = "standard"
  location = "europe-west1"
}

resource "google_container_cluster" "from_variable" {
  name               = "configurable"
  location           = "europe-west1"
  enable_legacy_abac = var.legacy_abac
}
