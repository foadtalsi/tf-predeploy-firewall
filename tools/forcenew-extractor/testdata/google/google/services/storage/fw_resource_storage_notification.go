package storage

func init() {
	registry.FrameworkResource{
		Name:        "google_storage_notification",
		ProductName: "storage",
		Func:        NewStorageNotificationResource,
	}.Register()
}

func NewStorageNotificationResource() resource.Resource {
	return &storageNotificationResource{}
}

type storageNotificationResource struct{}

func (r *storageNotificationResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"bucket": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"self_link": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}
