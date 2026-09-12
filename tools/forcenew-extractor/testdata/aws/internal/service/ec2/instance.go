package ec2

// A resolved resource with no ForceNew fields must be counted separately from an unreadable
// resource.

// @SDKResource("aws_instance", name="Instance")
func ResourceInstance() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"instance_type": {
				Type:     schema.TypeString,
				Optional: true,
			},
		},
	}
}
