package tpgiamresource

// The shared IAM constructor: its ForceNew arguments are split between this
// base schema and the parent schema each caller passes in.

var IamMemberBaseSchema = map[string]*schema.Schema{
	"role": {
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
	},
	"member": {
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
	},
	"etag": {
		Type:     schema.TypeString,
		Computed: true,
	},
}

func ResourceIamMember(parentSpecificSchema map[string]*schema.Schema, newUpdaterFunc NewResourceIamUpdaterFunc, options ...func(*IamSettings)) *schema.Resource {
	return &schema.Resource{
		Schema: tpgresource.MergeSchemas(IamMemberBaseSchema, parentSpecificSchema),
	}
}
