# Positives: ingress from the whole internet.
resource "google_compute_firewall" "ssh_from_anywhere" {
  name          = "allow-ssh"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "rdp_from_anywhere" {
  name          = "allow-rdp"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
}

resource "google_compute_firewall" "explicit_ingress" {
  name          = "allow-http"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_firewall" "mixed_ranges" {
  name          = "allow-db"
  network       = "default"
  source_ranges = ["10.0.0.0/8", "0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["5432"]
  }
}

resource "google_compute_firewall" "all_protocols" {
  name          = "allow-all"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "all"
  }
}

resource "google_sql_database_instance" "open" {
  name             = "orders"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "anyone"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_sql_database_instance" "open_among_others" {
  name             = "billing"
  database_version = "MYSQL_8_0"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "office"
        value = "203.0.113.0/24"
      }
      authorized_networks {
        name  = "temporary"
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_sql_database_instance" "open_replica" {
  name                 = "orders-replica"
  master_instance_name = "orders"
  database_version     = "POSTGRES_16"
  region               = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        value = "0.0.0.0/0"
      }
    }
  }
}

resource "google_container_cluster" "open_control_plane" {
  name     = "web"
  location = "europe-west1"

  master_authorized_networks_config {
    cidr_blocks {
      display_name = "anyone"
      cidr_block   = "0.0.0.0/0"
    }
  }
}

resource "google_container_cluster" "open_among_others" {
  name     = "batch"
  location = "europe-west1"

  master_authorized_networks_config {
    cidr_blocks {
      display_name = "vpn"
      cidr_block   = "10.8.0.0/16"
    }
    cidr_blocks {
      display_name = "debug"
      cidr_block   = "0.0.0.0/0"
    }
  }
}

# Near misses.

# A deny rule from everywhere is a guardrail, not an opening.
resource "google_compute_firewall" "deny_from_anywhere" {
  name          = "deny-telnet"
  network       = "default"
  priority      = 100
  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "tcp"
    ports    = ["23"]
  }
}

resource "google_compute_firewall" "egress_to_anywhere" {
  name               = "allow-egress"
  network            = "default"
  direction          = "EGRESS"
  destination_ranges = ["0.0.0.0/0"]
  source_ranges      = ["0.0.0.0/0"]

  allow {
    protocol = "all"
  }
}

resource "google_compute_firewall" "disabled" {
  name          = "allow-ssh-break-glass"
  network       = "default"
  disabled      = true
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "iap_only" {
  name          = "allow-ssh-iap"
  network       = "default"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "internal" {
  name          = "allow-internal"
  network       = "default"
  source_ranges = ["10.128.0.0/9"]

  allow {
    protocol = "all"
  }
}

resource "google_compute_firewall" "from_variable" {
  name          = "allow-https"
  network       = "default"
  source_ranges = var.allowed_ranges

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_sql_database_instance" "office_only" {
  name             = "inventory"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "office"
        value = "203.0.113.0/24"
      }
    }
  }
}

resource "google_sql_database_instance" "private_ip" {
  name             = "ledger"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
    ip_configuration {
      ipv4_enabled    = false
      private_network = "projects/acme/global/networks/default"
    }
  }
}

resource "google_container_cluster" "vpn_only" {
  name     = "internal"
  location = "europe-west1"

  master_authorized_networks_config {
    cidr_blocks {
      display_name = "vpn"
      cidr_block   = "10.8.0.0/16"
    }
  }
}

resource "google_container_cluster" "from_variable" {
  name     = "shared"
  location = "europe-west1"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = var.admin_range
    }
  }
}
