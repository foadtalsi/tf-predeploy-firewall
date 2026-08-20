package ec2

// Aucun ForceNew nulle part : la ressource doit apparaître comme vue et
// résolue, mais ne rien contribuer à l'index. Une ressource sans ForceNew et
// une ressource que l'extracteur n'a pas su lire ne doivent pas se ressembler.

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
