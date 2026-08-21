package rds

// @SDKResource("aws_db_instance", name="Instance")
func ResourceInstance() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"identifier": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
			},
			"allocated_storage": {
				Type:     schema.TypeInt,
				Optional: true,
			},
			"restore_to_point_in_time": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"source_db_instance_identifier": {
							Type:     schema.TypeString,
							Optional: true,
							ForceNew: true,
						},
					},
				},
			},
		},
	}
}
