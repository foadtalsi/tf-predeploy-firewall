resource "azurerm_storage_account" "data" {
  name                     = "acmedata"
  resource_group_name      = "rg-data"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "GRS"
}
