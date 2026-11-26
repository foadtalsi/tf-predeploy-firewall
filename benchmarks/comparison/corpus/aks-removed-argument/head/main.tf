resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-main"
  location            = "westeurope"
  resource_group_name = "rg-aks"
  dns_prefix          = "aksmain"

  default_node_pool {
    name                = "system"
    vm_size             = "Standard_D4s_v5"
    enable_auto_scaling = true
    min_count           = 2
    max_count           = 5
  }

  identity {
    type = "SystemAssigned"
  }
}
