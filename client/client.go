// Package sbxclient provides a pure stdlib Go client for the Docker Sandboxes
// (sandboxd) daemon API over a Unix domain socket.
//
// No external dependencies — only net/http, encoding/json, and friends.
package sbxclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
)

// ── Socket helpers ──────────────────────────────────────────────────────────

// DefaultSocketPath returns the default sandboxd Unix socket path for the
// current operating system.
func DefaultSocketPath() string {
	switch runtime.GOOS {
	case "darwin":
		home, _ := os.UserHomeDir()
		return home + "/Library/Application Support/com.docker.sandboxes/sandboxes/sandboxd/sandboxd.sock"
	case "linux":
		return "/run/sandboxd/sandboxd.sock"
	default:
		return ""
	}
}

// UnixSocketDialer returns an http.Transport whose DialContext connects to the
// given Unix socket path. Pass this to http.Client when constructing a Client.
func UnixSocketDialer(socketPath string) *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}
}

// ── Client ──────────────────────────────────────────────────────────────────

// Client is a sandboxd API client. Create one with NewClient.
type Client struct {
	hc  *http.Client
	url string // e.g. "http://localhost"
}

// NewClient creates a new sandboxd API client.
//
//   client := sbxclient.NewClient("http://localhost",
//       sbxclient.WithHTTPClient(&http.Client{
//           Transport: sbxclient.UnixSocketDialer(sbxclient.DefaultSocketPath()),
//       }))
func NewClient(baseURL string, opts ...Option) *Client {
	c := &Client{url: strings.TrimRight(baseURL, "/")}
	for _, o := range opts {
		o(c)
	}
	if c.hc == nil {
		c.hc = http.DefaultClient
	}
	return c
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the underlying HTTP client (e.g. one configured with a
// Unix socket dialer).
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.hc = hc }
}

// ── Generic HTTP helpers ────────────────────────────────────────────────────

func (c *Client) doRequest(ctx context.Context, method, path string, body, resp interface{}) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.url+path, reqBody)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	r, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = r.Body.Close() }()

	// Read full body for error messages
	raw, _ := io.ReadAll(r.Body)

	if r.StatusCode >= 400 {
		var errResp Error
		if json.Unmarshal(raw, &errResp) == nil && errResp.Message != "" {
			return &APIError{StatusCode: r.StatusCode, Message: errResp.Message}
		}
		return &APIError{StatusCode: r.StatusCode, Message: strings.TrimSpace(string(raw))}
	}

	if resp != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, resp); err != nil {
			return fmt.Errorf("unmarshal response: %w", err)
		}
	}
	return nil
}

// APIError represents a non-2xx response from the sandboxd daemon.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("sandboxd API error %d: %s", e.StatusCode, e.Message)
}

// ── Schemas (from sbx-openapi.yaml / sbx-api-guide.md) ──────────────────────

type Error struct {
	Message string `json:"message"`
}

type DaemonHealth struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	Status     string `json:"status"` // "healthy" | "unhealthy"
	Message    string `json:"message,omitempty"`
}

type DaemonInfo struct {
	SandboxdSocket string `json:"sandboxd_socket"`
	ProxySocket    string `json:"proxy_socket"`
}

type Runtime struct {
	ID    string       `json:"ID"`
	Spec  RuntimeSpec  `json:"Spec"`
	State RuntimeState `json:"State"`
}

type RuntimeSpec struct {
	RuntimeName          string          `json:"RuntimeName"`
	AgentName            string          `json:"AgentName"`
	WorkspaceDir         string          `json:"WorkspaceDir"`
	AdditionalWorkspaces []string        `json:"AdditionalWorkspaces,omitempty"`
	Profile              string          `json:"Profile,omitempty"`
	PatchClaudeSettings  bool            `json:"PatchClaudeSettings,omitempty"`
	Detached             bool            `json:"Detached,omitempty"`
	PullPolicy           string          `json:"PullPolicy,omitempty"`
	Credentials          *Credentials    `json:"Credentials,omitempty"`
	Services             *ServicesConfig `json:"Services,omitempty"`
}

type RuntimeState struct {
	Running      bool              `json:"Running"`
	SocketPath   string            `json:"SocketPath"`
	NetworkName  string            `json:"NetworkName"`
	ProxyEnvVars map[string]string `json:"ProxyEnvVars"`
}

type Credentials struct {
	Scope         string                 `json:"Scope"`
	Services      []string               `json:"Services"`
	Sources       map[string]string      `json:"Sources"`
	Values        []interface{}          `json:"Values"`
	CustomSecrets []CustomSecret         `json:"CustomSecrets"`
}

type CustomSecret struct {
	Target   string `json:"target"`
	EnvName  string `json:"env_name"`
	Sentinel string `json:"sentinel"`
	Value    string `json:"value"`
}

type ServicesConfig struct {
	Domains       map[string]string            `json:"Domains"`
	AuthConfig    map[string]AuthServiceConfig `json:"AuthConfig"`
	AllowedDomains []string                    `json:"AllowedDomains,omitempty"`
	DeniedDomains  []string                    `json:"DeniedDomains,omitempty"`
}

type AuthServiceConfig struct {
	HeaderName  string `json:"header_name"`
	ValueFormat string `json:"value_format"`
}

// ── Policy ──────────────────────────────────────────────────────────────────

type PolicyRule struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`     // "network"
	Origin    string   `json:"origin"`   // "local" | "sandbox"
	Decision  string   `json:"decision"` // "allow" | "deny"
	Status    string   `json:"status"`   // "active" | "inactive"
	Resources []string `json:"resources"`
	Sandbox   *string  `json:"sandbox"`
}

type PolicyActionAllow struct {
	Action    string   `json:"action"`            // "allow"
	Resources []string `json:"resources"`
	Scope     string   `json:"scope,omitempty"`
}

type PolicyActionDeny struct {
	Action    string   `json:"action"`    // "deny"
	Resources []string `json:"resources"`
}

type PolicyActionRemoveResource struct {
	Action    string   `json:"action"`    // "remove-resource"
	Resources []string `json:"resources"`
}

type PolicyActionRemoveID struct {
	Action string `json:"action"` // "remove-id"
	ID     string `json:"id"`
}

// PolicyAction is a union type used for serializing the actions array.
type PolicyAction map[string]interface{}

type ApplyPolicyRequest struct {
	Actions []PolicyAction `json:"actions"`
}

type PolicyActionResult struct {
	Action    string  `json:"action"`
	Resources []string `json:"resources,omitempty"`
	ID        string  `json:"id,omitempty"`
	Error     *string `json:"error,omitempty"`
}

type ApplyPolicyResponse struct {
	Results []PolicyActionResult `json:"results"`
}

type PolicySetupStatus struct {
	Needed bool `json:"needed"`
}

type PolicySetupRequest struct {
	Preset string `json:"preset"` // "balanced" | "allow-all" | "deny-all"
}

type PolicySetupResponse struct {
	Applied            bool   `json:"applied"`
	AlreadyConfigured  bool   `json:"already_configured"`
	ExistingPreset     string `json:"existing_preset,omitempty"`
}

type PolicyProfilesResponse struct {
	Profiles []interface{} `json:"profiles"`
}

// ── Templates ───────────────────────────────────────────────────────────────

type Template struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	Flavor     string `json:"flavor"`
	CreatedAt  string `json:"created_at"`
	Size       int64  `json:"size"`
}

// ── API Methods ─────────────────────────────────────────────────────────────

// GetDaemonHealth returns the daemon health check.
func (c *Client) GetDaemonHealth(ctx context.Context) (*DaemonHealth, error) {
	log.Printf("[sbx] GetDaemonHealth ...")
	var resp DaemonHealth
	if err := c.doRequest(ctx, http.MethodGet, "/daemon/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetDaemonInfo returns daemon configuration.
func (c *Client) GetDaemonInfo(ctx context.Context) (*DaemonInfo, error) {
	log.Printf("[sbx] GetDaemonInfo ...")
	var resp DaemonInfo
	if err := c.doRequest(ctx, http.MethodGet, "/daemon/info", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListSandboxes returns all sandbox runtimes.
func (c *Client) ListSandboxes(ctx context.Context) ([]Runtime, error) {
	log.Printf("[sbx] ListSandboxes ...")
	var resp []Runtime
	if err := c.doRequest(ctx, http.MethodGet, "/runtime", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateSandbox creates a new sandbox.
func (c *Client) CreateSandbox(ctx context.Context, spec RuntimeSpec) (*Runtime, error) {
	log.Printf("[sbx] CreateSandbox name=%s ...", spec.RuntimeName)
	body := map[string]RuntimeSpec{"spec": spec}
	var resp Runtime
	if err := c.doRequest(ctx, http.MethodPost, "/runtime", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetRuntime returns a single runtime by name (GET /runtime/{name}).
// Returns the full Runtime including Credentials.CustomSecrets in cleartext.
func (c *Client) GetRuntime(ctx context.Context, name string) (*Runtime, error) {
	log.Printf("[sbx] GetRuntime name=%s ...", name)
	var resp Runtime
	if err := c.doRequest(ctx, http.MethodGet, "/runtime/"+name, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ExtractCustomSecrets deduplicates CustomSecret entries across all runtimes.
// The returned map is keyed by env_name (e.g. "MISTRAL_API_KEY").
// Within each key, secrets are deduplicated by sentinel — the first occurrence
// of a given sentinel wins. This means the most recently seen value for each
// sentinel is preserved, but duplicate sentinels across runtimes are ignored.
func ExtractCustomSecrets(runtimes []Runtime) map[string][]CustomSecret {
	seen := make(map[string]map[string]bool) // env_name → set of sentinels
	result := make(map[string][]CustomSecret)
	for _, rt := range runtimes {
		if rt.Spec.Credentials == nil {
			continue
		}
		for _, cs := range rt.Spec.Credentials.CustomSecrets {
			if cs.EnvName == "" || cs.Value == "" {
				continue
			}
			if seen[cs.EnvName] == nil {
				seen[cs.EnvName] = make(map[string]bool)
			}
			if seen[cs.EnvName][cs.Sentinel] {
				continue // already have this sentinel
			}
			seen[cs.EnvName][cs.Sentinel] = true
			result[cs.EnvName] = append(result[cs.EnvName], cs)
		}
	}
	return result
}

// DeleteSandbox deletes a sandbox by name.
func (c *Client) DeleteSandbox(ctx context.Context, name string) error {
	log.Printf("[sbx] DeleteSandbox name=%s ...", name)
	return c.doRequest(ctx, http.MethodDelete, "/runtime/"+name, nil, nil)
}

// StartRuntime starts a sandbox runtime (POST /runtime/{name}/start).
// The Docker container must already exist.
func (c *Client) StartRuntime(ctx context.Context, name string) error {
	log.Printf("[sbx] StartRuntime name=%s ...", name)
	return c.doRequest(ctx, http.MethodPost, "/runtime/"+name+"/start", nil, nil)
}

// SyncRuntime pushes credentials/services configuration to a sandbox
// runtime (POST /runtime/{name}/sync). This triggers sandboxd to inject
// SSH keys, auth tokens, and service configs into the running container.
//
// The spec should include the full RuntimeSpec (especially Credentials
// and Services). Returns the updated Runtime state.
func (c *Client) SyncRuntime(ctx context.Context, name string, spec RuntimeSpec) (*Runtime, error) {
	log.Printf("[sbx] SyncRuntime name=%s ...", name)
	var resp Runtime
	if err := c.doRequest(ctx, http.MethodPost, "/runtime/"+name+"/sync", spec, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// StopRuntime stops a sandbox runtime (POST /runtime/{name}/stop).
func (c *Client) StopRuntime(ctx context.Context, name string) error {
	log.Printf("[sbx] StopRuntime name=%s ...", name)
	return c.doRequest(ctx, http.MethodPost, "/runtime/"+name+"/stop", nil, nil)
}

// ListPolicyRules returns all network policy rules.
func (c *Client) ListPolicyRules(ctx context.Context) ([]PolicyRule, error) {
	log.Printf("[sbx] ListPolicyRules ...")
	var resp struct {
		Rules []PolicyRule `json:"rules"`
	}
	if err := c.doRequest(ctx, http.MethodGet, "/policy/rules", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Rules, nil
}

// ApplyPolicyActions sends one or more policy actions.
func (c *Client) ApplyPolicyActions(ctx context.Context, actions []PolicyAction) (*ApplyPolicyResponse, error) {
	log.Printf("[sbx] ApplyPolicyActions ...")
	body := ApplyPolicyRequest{Actions: actions}
	var resp ApplyPolicyResponse
	if err := c.doRequest(ctx, http.MethodPost, "/policy/rules", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AllowPolicy adds an allow rule. If scope is non-empty, it is sandbox-scoped.
func (c *Client) AllowPolicy(ctx context.Context, resources []string, scope string) (*ApplyPolicyResponse, error) {
	log.Printf("[sbx] AllowPolicy ...")
	a := PolicyAction{
		"action":    "allow",
		"resources": resources,
	}
	if scope != "" {
		a["scope"] = scope
	}
	return c.ApplyPolicyActions(ctx, []PolicyAction{a})
}

// DenyPolicy adds a deny rule.
func (c *Client) DenyPolicy(ctx context.Context, resources []string) (*ApplyPolicyResponse, error) {
	log.Printf("[sbx] DenyPolicy ...")
	return c.ApplyPolicyActions(ctx, []PolicyAction{
		{"action": "deny", "resources": resources},
	})
}

// RemovePolicyResource removes all rules matching the given resources.
func (c *Client) RemovePolicyResource(ctx context.Context, resources []string) (*ApplyPolicyResponse, error) {
	log.Printf("[sbx] RemovePolicyResource ...")
	return c.ApplyPolicyActions(ctx, []PolicyAction{
		{"action": "remove-resource", "resources": resources},
	})
}

// RemovePolicyRule removes a single rule by ID.
func (c *Client) RemovePolicyRule(ctx context.Context, id string) (*ApplyPolicyResponse, error) {
	log.Printf("[sbx] RemovePolicyRule id=%s ...", id)
	return c.ApplyPolicyActions(ctx, []PolicyAction{
		{"action": "remove-id", "id": id},
	})
}

// CheckPolicySetup returns whether policy setup is needed.
func (c *Client) CheckPolicySetup(ctx context.Context) (*PolicySetupStatus, error) {
	log.Printf("[sbx] CheckPolicySetup ...")
	var resp PolicySetupStatus
	if err := c.doRequest(ctx, http.MethodGet, "/policy/setup", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SetDefaultPolicy configures the default network policy profile.
func (c *Client) SetDefaultPolicy(ctx context.Context, preset string) (*PolicySetupResponse, error) {
	log.Printf("[sbx] SetDefaultPolicy preset=%s ...", preset)
	body := PolicySetupRequest{Preset: preset}
	var resp PolicySetupResponse
	if err := c.doRequest(ctx, http.MethodPost, "/policy/setup", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListPolicyProfiles returns available policy profiles.
func (c *Client) ListPolicyProfiles(ctx context.Context) ([]interface{}, error) {
	log.Printf("[sbx] ListPolicyProfiles ...")
	var resp PolicyProfilesResponse
	if err := c.doRequest(ctx, http.MethodGet, "/policy/profiles", nil, &resp); err != nil {
		return nil, err
	}
	return resp.Profiles, nil
}

// GetNetworkLog returns the current network log of allowed and blocked hosts.
func (c *Client) GetNetworkLog(ctx context.Context) (*NetworkLog, error) {
	log.Printf("[sbx] GetNetworkLog ...")
	var resp NetworkLog
	if err := c.doRequest(ctx, http.MethodGet, "/network/log", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListTemplates returns available sandbox templates.
func (c *Client) ListTemplates(ctx context.Context) ([]Template, error) {
	log.Printf("[sbx] ListTemplates ...")
	var resp []Template
	if err := c.doRequest(ctx, http.MethodGet, "/template", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ── Network Log ─────────────────────────────────────────────────────────────

// NetworkLogEntry represents a single entry in the network log.
type NetworkLogEntry struct {
	Host       string `json:"host"`
	VMName     string `json:"vm_name"`
	ProxyType  string `json:"proxy_type"`
	Rule       string `json:"rule"`
	LastSeen   string `json:"last_seen"`
	Since      string `json:"since"`
	CountSince int    `json:"count_since"`
	Reason     string `json:"reason"`
}

// NetworkLog summarizes allowed and blocked network hosts.
type NetworkLog struct {
	BlockedHosts []NetworkLogEntry `json:"blocked_hosts"`
	AllowedHosts []NetworkLogEntry `json:"allowed_hosts"`
}

// ── Ports ────────────────────────────────────────────────────────────────────

// PortMapping represents a published port from a sandbox to the host.
type PortMapping struct {
	ID          string `json:"id,omitempty"`
	HostPort    int    `json:"host_port"`
	SandboxPort int    `json:"sandbox_port"`
	HostIP      string `json:"host_ip,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

// PublishPortRequest is the request body for publishing a port.
type PublishPortRequest struct {
	HostPort    *int   `json:"host_port,omitempty"`
	SandboxPort int    `json:"sandbox_port"`
	Protocol    string `json:"protocol,omitempty"`
}

// UnpublishPortRequest is the request body for unpublishing a port.
type UnpublishPortRequest struct {
	HostPort    int    `json:"host_port"`
	SandboxPort int    `json:"sandbox_port"`
	HostIP      string `json:"host_ip,omitempty"`
}

// ListPorts returns all published port mappings for a sandbox.
func (c *Client) ListPorts(ctx context.Context, sandboxName string) ([]PortMapping, error) {
	log.Printf("[sbx] ListPorts sandboxName=%s ...", sandboxName)
	var resp []PortMapping
	if err := c.doRequest(ctx, http.MethodGet, "/runtime/"+sandboxName+"/ports", nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// PublishPort publishes a sandbox port to the host.
func (c *Client) PublishPort(ctx context.Context, sandboxName string, req PublishPortRequest) ([]PortMapping, error) {
	log.Printf("[sbx] PublishPort sandboxName=%s ...", sandboxName)
	var resp []PortMapping
	if err := c.doRequest(ctx, http.MethodPost, "/runtime/"+sandboxName+"/ports", req, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// UnpublishPort removes a port mapping.
func (c *Client) UnpublishPort(ctx context.Context, sandboxName string, req UnpublishPortRequest) error {
	log.Printf("[sbx] UnpublishPort sandboxName=%s ...", sandboxName)
	return c.doRequest(ctx, http.MethodDelete, "/runtime/"+sandboxName+"/ports", req, nil)
}
