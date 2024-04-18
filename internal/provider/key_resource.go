package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"text/template"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/pbkdf2"
)

var (
	_ resource.Resource = &KeyResource{}
)

func NewKeyResource() resource.Resource {
	return &KeyResource{}
}

type KeyResource struct{}

func (r *KeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_key"
}

func (r *KeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "PBKDF2 derived key.",

		Attributes: map[string]schema.Attribute{
			"iterations": schema.Int64Attribute{
				MarkdownDescription: "Number of iterations.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(100000),
			},
			"format": schema.StringAttribute{
				MarkdownDescription: "Output format; will additionally be base64 encoded.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("{{ printf \"%s:%s\" (b64enc .Salt) (b64enc .Key) }}"),
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "The password input to encrypt.",
				Required:            true,
				Sensitive:           true,
			},
			"result": schema.StringAttribute{
				MarkdownDescription: "The generated key result.",
				Computed:            true,
				Sensitive:           true,
			},
		},
	}
}

type KeyResourceData struct {
	Iterations types.Int64  `tfsdk:"iterations"`
	Format     types.String `tfsdk:"format"`
	Password   types.String `tfsdk:"password"`
	Result     types.String `tfsdk:"result"`
}

type toFmt struct {
	Iterations int
	Salt       []byte
	Key        []byte
}

type KeyRequest struct {
	Plan *tfsdk.Plan
}

type KeyResponse struct {
	State       *tfsdk.State
	Diagnostics *diag.Diagnostics
}

func bin(len int, data int) string {
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(data))
	return string(bs[8-len:])
}

func b64enc(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func generate(ctx context.Context, req KeyRequest, resp *KeyResponse) {
	var plan KeyResourceData
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	var salt = make([]byte, 16)
	_, err := rand.Read(salt[:])
	if err != nil {
		resp.Diagnostics.AddError("Salt Error", err.Error())
		return
	}
	dk := pbkdf2.Key([]byte(plan.Password.ValueString()), salt, int(plan.Iterations.ValueInt64()), 32, sha256.New)
	var key bytes.Buffer
	formatTemplate := template.New("format")
	formatTemplate.Funcs(template.FuncMap{
		"bin":    bin,
		"b64enc": b64enc,
	})
	_, err = formatTemplate.Parse(plan.Format.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Format Error", err.Error())
		return
	}
	err = formatTemplate.Execute(&key, toFmt{
		Iterations: int(plan.Iterations.ValueInt64()),
		Salt:       salt,
		Key:        dk,
	})
	if err != nil {
		resp.Diagnostics.AddError("Format Error", err.Error())
		return
	}
	result := key.String()
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("iterations"), plan.Iterations)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("format"), plan.Format)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("password"), plan.Password)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("result"), result)...)
}

func (r KeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	generate(ctx, KeyRequest{Plan: &req.Plan}, &KeyResponse{State: &resp.State, Diagnostics: &resp.Diagnostics})
}

func (r KeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Not needed
}

func (r KeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	generate(ctx, KeyRequest{Plan: &req.Plan}, &KeyResponse{State: &resp.State, Diagnostics: &resp.Diagnostics})
}

func (r KeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.State.RemoveResource(ctx)
}
