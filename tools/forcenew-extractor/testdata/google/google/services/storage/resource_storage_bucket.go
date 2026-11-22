package storage

func ResourceStorageBucket() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"force_destroy": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			// A nested block whose schema comes from a helper function.
			"custom_placement_config": customPlacementConfigSchema(),
			"retention_policy": {
				Type:     schema.TypeList,
				Optional: true,
				Elem:     retentionPolicyElemSchema(),
			},
		},
	}
}

func customPlacementConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"data_locations": {
					Type:     schema.TypeSet,
					Required: true,
					ForceNew: true,
				},
			},
		},
	}
}

func retentionPolicyElemSchema() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"is_locked": {
				Type:     schema.TypeBool,
				Optional: true,
				ForceNew: true,
			},
			"retention_period": {
				Type:     schema.TypeInt,
				Required: true,
			},
		},
	}
}

// A data source carries ForceNew-looking fields too, but is never replaced and
// must not reach the index.
func DataSourceGoogleStorageBucket() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
		},
	}
}

func init() {
	registry.Schema{
		Name:        "google_storage_bucket",
		ProductName: "storage",
		Type:        registry.SchemaTypeResource,
		Schema:      ResourceStorageBucket(),
	}.Register()
	registry.Schema{
		Name:        "google_storage_bucket",
		ProductName: "storage",
		Type:        registry.SchemaTypeDataSource,
		Schema:      DataSourceGoogleStorageBucket(),
	}.Register()
}
