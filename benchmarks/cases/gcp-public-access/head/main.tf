# Positives: grants to anyone on the internet, or anyone with a Google account.
resource "google_storage_bucket_iam_member" "public_read" {
  bucket = "acme-assets"
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "google_storage_bucket_iam_binding" "public_among_others" {
  bucket  = "acme-reports"
  role    = "roles/storage.objectViewer"
  members = ["group:analysts@acme.example", "allUsers"]
}

resource "google_project_iam_member" "any_google_account" {
  project = "acme-prod"
  role    = "roles/viewer"
  member  = "allAuthenticatedUsers"
}

resource "google_pubsub_topic_iam_member" "public_publish" {
  topic  = "events"
  role   = "roles/pubsub.publisher"
  member = "allUsers"
}

resource "google_bigquery_dataset_iam_member" "public_dataset" {
  dataset_id = "analytics"
  role       = "roles/bigquery.dataViewer"
  member     = "allAuthenticatedUsers"
}

data "google_iam_policy" "public_bucket" {
  binding {
    role    = "roles/storage.objectViewer"
    members = ["allUsers"]
  }
}

resource "google_storage_bucket_acl" "public_read" {
  bucket         = "acme-public"
  predefined_acl = "publicRead"
}

resource "google_storage_bucket_acl" "public_read_write" {
  bucket         = "acme-uploads"
  predefined_acl = "publicReadWrite"
}

resource "google_storage_bucket_acl" "authenticated_read" {
  bucket         = "acme-shared"
  predefined_acl = "authenticatedRead"
}

resource "google_storage_bucket_acl" "role_entity_all_users" {
  bucket      = "acme-site"
  role_entity = ["OWNER:project-owners-123456", "READER:allUsers"]
}

resource "google_storage_default_object_acl" "all_authenticated" {
  bucket      = "acme-docs"
  role_entity = ["READER:allAuthenticatedUsers"]
}

resource "google_storage_object_access_control" "public_object" {
  bucket = "acme-site"
  object = "index.html"
  role   = "READER"
  entity = "allUsers"
}

resource "google_storage_bucket_access_control" "public_bucket" {
  bucket = "acme-site"
  role   = "READER"
  entity = "allUsers"
}

# Near misses.

# A public HTTP endpoint: invoker for allUsers is how Cloud Run and Cloud Functions
# serve the internet, and the service authenticates its callers itself.
resource "google_cloud_run_v2_service_iam_member" "public_api" {
  name     = "api"
  location = "europe-west1"
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloudfunctions2_function_iam_member" "webhook" {
  cloud_function = "stripe-webhook"
  location       = "europe-west1"
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}

resource "google_storage_bucket_iam_member" "group_read" {
  bucket = "acme-reports"
  role   = "roles/storage.objectViewer"
  member = "group:analysts@acme.example"
}

resource "google_project_iam_member" "domain" {
  project = "acme-prod"
  role    = "roles/viewer"
  member  = "domain:acme.example"
}

resource "google_storage_bucket_iam_member" "user_named_like_it" {
  bucket = "acme-reports"
  role   = "roles/storage.objectViewer"
  member = "user:allusers-team@acme.example"
}

resource "google_storage_bucket_iam_member" "from_variable" {
  bucket = "acme-reports"
  role   = "roles/storage.objectViewer"
  member = var.reader
}

resource "google_storage_bucket_acl" "private" {
  bucket         = "acme-private"
  predefined_acl = "private"
}

resource "google_storage_bucket_acl" "project_private" {
  bucket         = "acme-internal"
  predefined_acl = "projectPrivate"
}

resource "google_storage_object_access_control" "group" {
  bucket = "acme-site"
  object = "draft.html"
  role   = "READER"
  entity = "group-editors@acme.example"
}

resource "google_storage_bucket_acl" "owner_entities" {
  bucket      = "acme-site"
  role_entity = ["OWNER:project-owners-123456", "READER:project-viewers-123456"]
}
