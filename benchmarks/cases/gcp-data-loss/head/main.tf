# Positives: protection the provider turns on by default, switched off.
resource "google_sql_database_instance" "unprotected" {
  name                = "orders"
  database_version    = "POSTGRES_16"
  region              = "europe-west1"
  deletion_protection = false

  settings {
    tier = "db-custom-2-7680"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_bigquery_table" "unprotected" {
  dataset_id          = "analytics"
  table_id            = "events"
  deletion_protection = false
}

resource "google_spanner_database" "unprotected" {
  instance            = "main"
  name                = "ledger"
  deletion_protection = false
}

resource "google_bigtable_instance" "unprotected" {
  name                = "metrics"
  deletion_protection = false
}

resource "google_alloydb_cluster" "unprotected" {
  cluster_id          = "payments"
  location            = "europe-west1"
  deletion_protection = false
}

# Positives: a destroy empties the store instead of failing on it.
resource "google_storage_bucket" "force_destroy" {
  name          = "acme-uploads"
  location      = "EU"
  force_destroy = true
}

resource "google_storage_bucket" "force_destroy_logs" {
  name          = "acme-audit-logs"
  location      = "EU"
  force_destroy = true
}

resource "google_storage_bucket" "force_destroy_backups" {
  name          = "acme-backups"
  location      = "EU"
  force_destroy = true
}

resource "google_bigquery_dataset" "delete_contents" {
  dataset_id                 = "analytics"
  location                   = "EU"
  delete_contents_on_destroy = true
}

resource "google_bigquery_dataset" "delete_contents_raw" {
  dataset_id                 = "raw"
  location                   = "EU"
  delete_contents_on_destroy = true
}

# Near misses.
resource "google_sql_database_instance" "protected" {
  name                = "billing"
  database_version    = "POSTGRES_16"
  region              = "europe-west1"
  deletion_protection = true

  settings {
    tier = "db-custom-2-7680"
  }
}

resource "google_sql_database_instance" "default" {
  name             = "inventory"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
  }
}

# Off by default on a VM, and a VM holds no data its disks do not.
resource "google_compute_instance" "unprotected_vm" {
  name                = "worker"
  machine_type        = "e2-small"
  zone                = "europe-west1-b"
  deletion_protection = false

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    network = "default"
  }
}

resource "google_sql_database_instance" "from_variable" {
  name                = "reports"
  database_version    = "POSTGRES_16"
  region              = "europe-west1"
  deletion_protection = var.protect

  settings {
    tier = "db-custom-2-7680"
  }
}

resource "google_storage_bucket" "kept" {
  name          = "acme-archive"
  location      = "EU"
  force_destroy = false
}

resource "google_storage_bucket" "default" {
  name     = "acme-media"
  location = "EU"
}

resource "google_bigquery_dataset" "kept" {
  dataset_id                 = "curated"
  location                   = "EU"
  delete_contents_on_destroy = false
}

resource "google_storage_bucket" "from_variable" {
  name          = "acme-scratch"
  location      = "EU"
  force_destroy = var.ephemeral
}
