resource "google_storage_bucket" "reports" {
  name                        = "acme-reports"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
