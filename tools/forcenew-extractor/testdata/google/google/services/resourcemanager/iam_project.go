package resourcemanager

var IamProjectSchema = map[string]*schema.Schema{
	"project": {
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
	},
}

// A same-package wrapper around the shared constructor.
func ProjectIamMemberResource() *schema.Resource {
	return tpgiamresource.ResourceIamMember(IamProjectSchema, NewProjectIamUpdater)
}

func init() {
	registry.Schema{
		Name:        "google_project_iam_member",
		ProductName: "resourcemanager",
		Type:        registry.SchemaTypeIAMResource,
		Schema:      ProjectIamMemberResource(),
	}.Register()
}
