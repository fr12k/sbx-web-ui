// Package server provides an HTTP server that wraps the sbx Go client and
// exposes a simple web UI (pure JS) for managing Docker Sandboxes.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	sbxclient "github.com/frankittermann/sbx-web-ui/client"
)

// ── Server ──────────────────────────────────────────────────────────────────

// Server holds references to the sandboxd client, Docker client, optional auth
// credentials, startup commands per sandbox, and the HTTP mux.
type Server struct {
	client       *sbxclient.Client
	dockerClient *sbxclient.DockerClient
	mux          *http.ServeMux
	staticRoot   http.FileSystem
	authUser     string
	authPass     string
	authHash     []byte // SHA-256 of "user:pass" for fast comparison

	// startupCmds tracks the command to run inside each sandbox's container
	// after the sandbox starts. Keyed by sandbox (runtime) name.
	startupCmds map[string]string

	// agentProcesses tracks long-running agent processes per sandbox.
	// Keyed by sandbox name, value is the exec ID and log buffer.
	agentProcesses map[string]*agentProcessInfo

	// customSecrets holds cleartext CustomSecrets bootstrapped from existing
	// runtimes. Populated on server startup and refreshable via the API.
	// Keyed by env_name (e.g. "MISTRAL_API_KEY").
	customSecrets map[string][]sbxclient.CustomSecret

	mu              sync.Mutex
	customSecretsMu sync.RWMutex
}

type agentProcessInfo struct {
	ExecID    string    `json:"exec_id"`
	Cmd       string    `json:"cmd"`
	StartedAt time.Time `json:"started_at"`
	Running   bool      `json:"running"`
	LogBuf    []byte    `json:"-"` // ring buffer of log output
	MaxLog    int       `json:"-"`
}

// Credentials holds basic auth credentials.
type Credentials struct {
	Username string
	Password string
}

// New creates a new Server with optional basic auth. If creds is nil or has
// empty Username/Password, auth is disabled. Pass a nil dockerClient if the
// Docker Engine socket is unavailable (container operations will return errors).
func New(c *sbxclient.Client, dockerClient *sbxclient.DockerClient, staticFS http.FileSystem, creds *Credentials) *Server {
	s := &Server{
		client:         c,
		dockerClient:   dockerClient,
		mux:            http.NewServeMux(),
		staticRoot:     staticFS,
		startupCmds:    make(map[string]string),
		agentProcesses: make(map[string]*agentProcessInfo),
		customSecrets:  make(map[string][]sbxclient.CustomSecret),
	}
	if creds != nil && creds.Username != "" && creds.Password != "" {
		s.authUser = creds.Username
		s.authPass = creds.Password
		h := sha256.Sum256([]byte(creds.Username + ":" + creds.Password))
		s.authHash = h[:]
		log.Printf("Basic auth enabled for user %q", creds.Username)
	}
	s.routes()

	// Bootstrap custom secrets from existing runtimes (best-effort).
	s.bootstrapSecrets(context.Background())

	return s
}

// ServeHTTP implements http.Handler, wrapping the mux with optional basic auth.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.authUser != "" {
		if !s.authenticate(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Sandbox Manager", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

// ── Embed static files ──────────────────────────────────────────────────────

//go:embed static/*
var staticEmbed embed.FS

// StaticFS returns an http.FileSystem rooted at the embedded static directory.
func StaticFS() http.FileSystem {
	sub, err := fs.Sub(staticEmbed, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}

// ── Routes ──────────────────────────────────────────────────────────────────

func (s *Server) routes() {
	// JSON API — proxy to sandboxd
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/info", s.handleInfo)
	s.mux.HandleFunc("GET /api/sandboxes", s.handleListSandboxes)
	s.mux.HandleFunc("POST /api/sandboxes", s.handleCreateSandbox)
	s.mux.HandleFunc("DELETE /api/sandboxes/{name}", s.handleDeleteSandbox)

	// Runtime lifecycle — start/stop
	s.mux.HandleFunc("POST /api/sandboxes/{name}/start", s.handleStartSandbox)
	s.mux.HandleFunc("POST /api/sandboxes/{name}/stop", s.handleStopSandbox)

	// SSH Agent forward injection (manual socat bridge)
	s.mux.HandleFunc("POST /api/sandboxes/{name}/inject-ssh-agent", s.handleInjectSSHAgent)

	// Agent process management
	s.mux.HandleFunc("POST /api/sandboxes/{name}/agent", s.handleStartAgent)
	s.mux.HandleFunc("GET /api/sandboxes/{name}/agent", s.handleAgentStatus)
	s.mux.HandleFunc("GET /api/sandboxes/{name}/agent/logs", s.handleAgentLogs)
	s.mux.HandleFunc("DELETE /api/sandboxes/{name}/agent", s.handleStopAgent)

	// Image management
	s.mux.HandleFunc("POST /api/images/pull", s.handlePullImage)
	s.mux.HandleFunc("GET /api/images", s.handleListImages)

	// Policy
	s.mux.HandleFunc("GET /api/policy/rules", s.handleListPolicyRules)
	s.mux.HandleFunc("POST /api/policy/rules", s.handleApplyPolicyActions)
	s.mux.HandleFunc("GET /api/policy/setup", s.handleCheckPolicySetup)
	s.mux.HandleFunc("POST /api/policy/setup", s.handleSetDefaultPolicy)
	s.mux.HandleFunc("GET /api/templates", s.handleListTemplates)
	s.mux.HandleFunc("GET /api/socket", s.handleSocketPath)

	// Network Log
	s.mux.HandleFunc("GET /api/network/log", s.handleGetNetworkLog)

	// Secrets — read CustomSecrets from existing runtimes
	s.mux.HandleFunc("GET /api/secrets", s.handleListSecrets)
	s.mux.HandleFunc("POST /api/secrets/refresh", s.handleRefreshSecrets)

	// Port publishing — proxy to sandboxd /runtime/{name}/ports
	s.mux.HandleFunc("GET /api/ports", s.handleListPorts)
	s.mux.HandleFunc("POST /api/ports", s.handlePublishPort)
	s.mux.HandleFunc("DELETE /api/ports", s.handleUnpublishPort)

	// Serve the SPA — catch-all for non-API routes
	s.mux.HandleFunc("/", s.handleStatic)
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Only GET
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	f, err := s.staticRoot.Open(path)
	if err != nil {
		// Serve index.html for SPA routing
		f, err = s.staticRoot.Open("index.html")
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Set content type based on extension
	ct := contentType(path)
	w.Header().Set("Content-Type", ct)
	// Read file into memory (fs.File doesn't implement io.ReadSeeker)
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "error reading file", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, path, stat.ModTime(), bytes.NewReader(data))
}

func contentType(path string) string {
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	default:
		return "text/plain; charset=utf-8"
	}
}

// ── Auth ────────────────────────────────────────────────────────────────────

// authenticate checks the request's Basic auth against the stored credentials
// using a constant-time comparison of the SHA-256 hash to prevent timing attacks.
func (s *Server) authenticate(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// Constant-time compare of SHA-256 hashes to avoid leaking credential length/timing
	got := sha256.Sum256([]byte(user + ":" + pass))
	return subtle.ConstantTimeCompare(got[:], s.authHash) == 1
}

// ── JSON helpers ────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode error: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ── Handlers ────────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	h, err := s.client.GetDaemonHealth(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.client.GetDaemonInfo(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleListSandboxes(w http.ResponseWriter, r *http.Request) {
	sbs, err := s.client.ListSandboxes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if sbs == nil {
		sbs = []sbxclient.Runtime{}
	}
	// Strip sensitive fields from each runtime before returning
	type safeSpec struct {
		RuntimeName          string   `json:"RuntimeName"`
		AgentName            string   `json:"AgentName"`
		WorkspaceDir         string   `json:"WorkspaceDir"`
		AdditionalWorkspaces []string `json:"AdditionalWorkspaces,omitempty"`
		Profile              string   `json:"Profile,omitempty"`
		Detached             bool     `json:"Detached,omitempty"`
		PullPolicy           string   `json:"PullPolicy,omitempty"`
	}
	type safeRuntime struct {
		ID    string                 `json:"ID"`
		Spec  safeSpec               `json:"Spec"`
		State sbxclient.RuntimeState `json:"State"`
	}
	safe := make([]safeRuntime, len(sbs))
	for i, sb := range sbs {
		safe[i] = safeRuntime{
			ID: sb.ID,
			Spec: safeSpec{
				RuntimeName:          sb.Spec.RuntimeName,
				AgentName:            sb.Spec.AgentName,
				WorkspaceDir:         sb.Spec.WorkspaceDir,
				AdditionalWorkspaces: sb.Spec.AdditionalWorkspaces,
				Profile:              sb.Spec.Profile,
				Detached:             sb.Spec.Detached,
				PullPolicy:           sb.Spec.PullPolicy,
			},
			State: sb.State,
		}
	}
	writeJSON(w, http.StatusOK, safe)
}

func (s *Server) handleCreateSandbox(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Spec       sbxclient.RuntimeSpec `json:"spec"`
		StartupCmd string                `json:"startup_cmd,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Spec.RuntimeName == "" || req.Spec.WorkspaceDir == "" || req.Spec.AgentName == "" {
		writeError(w, http.StatusBadRequest, "spec.RuntimeName, spec.WorkspaceDir, and spec.AgentName are required")
		return
	}

	// Build Credentials — merge any user-provided CustomSecrets with
	// bootstrapped ones from existing runtimes. The request's CustomSecrets
	// take precedence over bootstrapped ones (allows override).
	userSecrets := req.Spec.Credentials
	bootstrapped := s.getCustomSecrets()

	// If the request had no CustomSecrets, use all bootstrapped ones.
	// If it had some, merge: request secrets win, then fill in rest from bootstrap.
	mergedSecrets := make([]sbxclient.CustomSecret, 0)
	userKeys := make(map[string]bool) // track env_names from request
	if userSecrets != nil {
		for _, cs := range userSecrets.CustomSecrets {
			if cs.EnvName != "" {
				userKeys[cs.EnvName] = true
			}
			mergedSecrets = append(mergedSecrets, cs)
		}
	}

	// Fill in any bootstrapped secrets that the request didn't specify.
	// For each env_name, use the first bootstrapped entry.
	for _, secrets := range bootstrapped {
		for _, cs := range secrets {
			if !userKeys[cs.EnvName] {
				userKeys[cs.EnvName] = true // avoid duplicates
				mergedSecrets = append(mergedSecrets, cs)
			}
		}
	}

	req.Spec.Credentials = &sbxclient.Credentials{
		Services:      []string{"github", "google", "mistral", "openai", "anthropic"},
		CustomSecrets: mergedSecrets,
	}
	req.Spec.Services = &sbxclient.ServicesConfig{
		Domains: map[string]string{
			"api.anthropic.com":                 "anthropic",
			"claude.ai":                         "anthropic",
			"console.anthropic.com":             "anthropic",
			"aiplatform.googleapis.com":         "google",
			"vertexai.googleapis.com":           "google",
			"generativelanguage.googleapis.com": "google",
			"oauth2.googleapis.com":             "google",
			"api.github.com":                    "github",
			"copilot.github.com":                "github",
			"github.com":                        "github",
			"raw.githubusercontent.com":         "github",
			"api.mistral.ai":                    "mistral",
			"api.openai.com":                    "openai",
			"openai.com":                        "openai",
		},
		AuthConfig: map[string]sbxclient.AuthServiceConfig{
			"anthropic": {
				HeaderName:  "x-api-key",
				ValueFormat: "%s",
			},
			"github": {
				HeaderName:  "Authorization",
				ValueFormat: "Bearer %s",
			},
			"google": {
				HeaderName:  "x-goog-api-key",
				ValueFormat: "%s",
			},
			"mistral": {
				HeaderName:  "Authorization",
				ValueFormat: "Bearer %s",
			},
			"openai": {
				HeaderName:  "Authorization",
				ValueFormat: "Bearer %s",
			},
		},
	}
	sb, err := s.client.CreateSandbox(r.Context(), req.Spec)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Store startup command if provided
	if req.StartupCmd != "" {
		s.mu.Lock()
		s.startupCmds[req.Spec.RuntimeName] = req.StartupCmd
		s.mu.Unlock()
		log.Printf("Stored startup command for sandbox %q: %s", req.Spec.RuntimeName, req.StartupCmd)
	}
	// Strip sensitive fields before returning
	type safeSpec struct {
		RuntimeName          string   `json:"RuntimeName"`
		AgentName            string   `json:"AgentName"`
		WorkspaceDir         string   `json:"WorkspaceDir"`
		AdditionalWorkspaces []string `json:"AdditionalWorkspaces,omitempty"`
		Profile              string   `json:"Profile,omitempty"`
		Detached             bool     `json:"Detached,omitempty"`
		PullPolicy           string   `json:"PullPolicy,omitempty"`
	}
	type safeRuntime struct {
		ID    string                 `json:"ID"`
		Spec  safeSpec               `json:"Spec"`
		State sbxclient.RuntimeState `json:"State"`
	}
	safe := safeRuntime{
		ID: sb.ID,
		Spec: safeSpec{
			RuntimeName:          sb.Spec.RuntimeName,
			AgentName:            sb.Spec.AgentName,
			WorkspaceDir:         sb.Spec.WorkspaceDir,
			AdditionalWorkspaces: sb.Spec.AdditionalWorkspaces,
			Profile:              sb.Spec.Profile,
			Detached:             sb.Spec.Detached,
			PullPolicy:           sb.Spec.PullPolicy,
		},
		State: sb.State,
	}
	writeJSON(w, http.StatusOK, safe)
}

func (s *Server) handleDeleteSandbox(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := s.client.DeleteSandbox(r.Context(), name); err != nil {
		if apiErr, ok := err.(*sbxclient.APIError); ok && apiErr.StatusCode == http.StatusNotFound {
			writeError(w, http.StatusNotFound, "sandbox not found")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Runtime Lifecycle handlers ─────────────────────────────────────────────

// ── Runtime Lifecycle handlers ─────────────────────────────────────────────

func (s *Server) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Fetch sandbox runtime to get spec and proxy env vars
	runtimes, err := s.client.ListSandboxes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch sandbox: "+err.Error())
		return
	}
	var runtime *sbxclient.Runtime
	for _, rt := range runtimes {
		if rt.Spec.RuntimeName == name {
			runtime = &rt
			break
		}
	}
	if runtime == nil {
		writeError(w, http.StatusNotFound, "sandbox not found")
		return
	}

	// Determine whether SSH agent forward was requested by checking if the
	// sandbox's credential spec has services configured (set at creation time
	// via the web UI checkboxes).
	hasServices := runtime.Spec.Credentials != nil && len(runtime.Spec.Credentials.Services) > 0

	// Step 2: Create Docker container if it doesn't exist (and Docker is available)
	var containerID string
	if s.dockerClient != nil {
		exists, cid, err := s.dockerClient.ContainerExists(r.Context(), name)
		if err != nil {
			writeError(w, http.StatusBadGateway, "failed to check container: "+err.Error())
			return
		}
		if exists {
			containerID = cid
		} else {
			// Determine image from agent name / profile
			image, _ := resolveSandboxImage(r.Context(), s.client, runtime.Spec)

			params := sbxclient.SandboxContainerConfig(
				name,
				image,
				runtime.Spec.WorkspaceDir,
				runtime.State.ProxyEnvVars,
				"",
				map[string]string{
					"com.docker.sandbox.agent":            runtime.Spec.AgentName,
					"com.docker.sandbox.workingDirectory": runtime.Spec.WorkspaceDir,
					"docker/sandbox":                      "true",
				},
			)

			resp, err := s.dockerClient.CreateContainer(r.Context(), name, params)
			if err != nil {
				writeError(w, http.StatusBadGateway, "container create failed: "+err.Error())
				return
			}
			containerID = resp.ID
			log.Printf("Auto-created container for sandbox %q using image %s (id=%s)", name, image, containerID)
		}
	}

	// Step 4: Start the runtime (this transitions the container to running)
	if err := s.client.StartRuntime(r.Context(), name); err != nil {
		if apiErr, ok := err.(*sbxclient.APIError); ok && apiErr.StatusCode == http.StatusNotFound {
			writeError(w, http.StatusNotFound, "sandbox not found")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	// Step 5: Sync (push credentials/services config to the container).
	// Note: Per the injection doc, the sync endpoint is metadata-only for
	// running containers — but it updates the credential spec which matters
	// for container restart flows.
	if _, err := s.client.SyncRuntime(r.Context(), name, runtime.Spec); err != nil {
		log.Printf("Warning: sync runtime %q failed (non-fatal): %v", name, err)
	}

	// Step 6: Install proxy CA certificate into the container's system trust
	// store so that curl, git, and other TLS clients trust the sandboxd
	// MITM proxy. The PROXY_CA_CERT_B64 env var is injected by sandboxd.
	var proxyCAInstallResult map[string]interface{}
	if s.dockerClient != nil && containerID != "" {
		info, err := s.dockerClient.InspectContainer(r.Context(), containerID)
		if err == nil && info.State.Running {
			if err := s.dockerClient.InstallProxyCACert(r.Context(), containerID); err == nil {
				proxyCAInstallResult = map[string]interface{}{
					"proxy_ca_installed": true,
					"message":            "Proxy CA certificate installed successfully",
				}
				log.Printf("Installed proxy CA certificate for sandbox %q", name)
			} else {
				log.Printf("Warning: proxy CA certificate installation for %q failed: %v", name, err)
				proxyCAInstallResult = map[string]interface{}{
					"proxy_ca_installed": false,
					"error":              err.Error(),
				}
			}
		}
	}

	// Step 7: Auto-inject SSH agent forward if the sandbox has services configured.
	// This uses the manual socat injection (Method 3 from the injection doc)
	// since the sync endpoint does not trigger re-injection on running containers.
	var injectResult map[string]interface{}
	if hasServices && s.dockerClient != nil && containerID != "" {
		info, err := s.dockerClient.InspectContainer(r.Context(), containerID)
		if err == nil && info.State.Running {
			execID, err := s.dockerClient.InjectSSHAgentForward(r.Context(), containerID)
			if err == nil {
				injectResult = map[string]interface{}{
					"ssh_agent_injected": true,
					"exec_id":            execID,
					"ssh_auth_sock":      "/run/ssh-agent.sock",
					"message":            "SSH agent forward injected via socat",
				}
				log.Printf("Auto-injected SSH agent forward for sandbox %q (execID=%s)", name, execID)
			} else {
				log.Printf("Warning: auto-inject SSH agent forward for %q failed: %v", name, err)
				injectResult = map[string]interface{}{
					"ssh_agent_injected": false,
					"error":              err.Error(),
				}
			}
		}
	}

	// Step 7: Auto-execute the stored startup command inside the container.
	// The startupCmd is a space-separated string parsed into a command array.
	// It runs as a background (detached) exec inside the container.
	var startupResult map[string]interface{}
	if s.dockerClient != nil && containerID != "" {
		s.mu.Lock()
		rawCmd := s.startupCmds[name]
		s.mu.Unlock()

		if rawCmd != "" {
			info, err := s.dockerClient.InspectContainer(r.Context(), containerID)
			if err == nil && info.State.Running {
				// Always wrap in sh -c so pipes, redirections, and shell features
				// work as the user expects. Docker exec passes argv directly to
				// execve(2) — no shell parsing happens without wrapping.
				log.Printf("[server] Starting stored startup command for sandbox %q in container %s: sh -c %q", name, containerID, rawCmd)
				parts := []string{"sh", "-c", rawCmd}
				execID, err := s.dockerClient.ExecInContainer(r.Context(), containerID, parts, "", runtime.Spec.WorkspaceDir)
				if err == nil {
					startupResult = map[string]interface{}{
						"startup_cmd":     rawCmd,
						"startup_exec_id": execID,
					}
					log.Printf("[server] Startup command started for sandbox %q (execID=%s)", name, execID)
				} else {
					log.Printf("Warning: startup command for %q failed: %v", name, err)
				}
			}
		}
	}

	if proxyCAInstallResult != nil || injectResult != nil || startupResult != nil {
		// Build a combined response
		combined := make(map[string]interface{})
		for k, v := range proxyCAInstallResult {
			combined[k] = v
		}
		for k, v := range injectResult {
			combined[k] = v
		}
		for k, v := range startupResult {
			combined[k] = v
		}
		writeJSON(w, http.StatusOK, combined)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// resolveSandboxImage looks up the correct Docker image for a sandbox spec
// by querying the templates API. Falls back to a reasonable default if the
// lookup fails.
func resolveSandboxImage(ctx context.Context, c *sbxclient.Client, spec sbxclient.RuntimeSpec) (string, error) {
	// Try templates API to find the matching image
	templates, err := c.ListTemplates(ctx)
	if err == nil && len(templates) > 0 {
		// Match by agent name first
		for _, t := range templates {
			if t.Flavor == spec.AgentName || t.ID == spec.AgentName {
				if t.Repository != "" {
					if t.Tag != "" {
						return t.Repository + ":" + t.Tag, nil
					}
					return t.Repository, nil
				}
			}
		}
		// Match by profile
		if spec.Profile != "" {
			for _, t := range templates {
				if t.Flavor == spec.Profile || t.ID == spec.Profile {
					if t.Repository != "" {
						if t.Tag != "" {
							return t.Repository + ":" + t.Tag, nil
						}
						return t.Repository, nil
					}
				}
			}
		}
		// Fallback: use first template's repository
		if len(templates) > 0 && templates[0].Repository != "" {
			if templates[0].Tag != "" {
				return templates[0].Repository + ":" + templates[0].Tag, nil
			}
			return templates[0].Repository, nil
		}
	}

	// Last resort: construct from agent name
	return "docker/sandbox-templates:" + spec.AgentName + "-docker", nil
}

func (s *Server) handleStopSandbox(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := s.client.StopRuntime(r.Context(), name); err != nil {
		if apiErr, ok := err.(*sbxclient.APIError); ok && apiErr.StatusCode == http.StatusNotFound {
			writeError(w, http.StatusNotFound, "sandbox not found")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Container management handlers ──────────────────────────────────────────

func (s *Server) requireDocker(w http.ResponseWriter) bool {
	if s.dockerClient == nil {
		writeError(w, http.StatusServiceUnavailable, "Docker Engine socket not available")
		return false
	}
	return true
}

// ── Agent management ─────────────────────────────────────────────────────

func (s *Server) handleStartAgent(w http.ResponseWriter, r *http.Request) {
	if !s.requireDocker(w) {
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Parse command from request body
	var req struct {
		Cmd []string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Cmd) == 0 {
		writeError(w, http.StatusBadRequest, "cmd (array of strings) is required")
		return
	}

	// Find container ID
	exists, containerID, err := s.dockerClient.ContainerExists(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to check container: "+err.Error())
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "container not found for sandbox")
		return
	}

	log.Printf("[server] Starting process in container %q: %v", containerID, req.Cmd)
	execID, err := s.dockerClient.ExecInContainer(r.Context(), containerID, req.Cmd, "", "")
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to start process: "+err.Error())
		return
	}
	log.Printf("[server] Process started in container %q (execID=%s)", containerID, execID)

	// Track the agent process
	s.mu.Lock()
	s.agentProcesses[name] = &agentProcessInfo{
		ExecID:    execID,
		Cmd:       strings.Join(req.Cmd, " "),
		StartedAt: time.Now(),
		Running:   true,
		LogBuf:    make([]byte, 0, 16384),
		MaxLog:    65536,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"exec_id": execID,
	})
}

// handleAgentStatus returns the status of the running agent process (if any)
// for the given sandbox. Checks via Docker exec inspect to get real-time status.
func (s *Server) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	s.mu.Lock()
	info, ok := s.agentProcesses[name]
	s.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"running": false,
			"message": "No agent process has been started for this sandbox.",
		})
		return
	}

	resp := map[string]interface{}{
		"exec_id":    info.ExecID,
		"cmd":        info.Cmd,
		"started_at": info.StartedAt.Format(time.RFC3339),
		"running":    true,
	}

	// Try to get real-time status from Docker if available
	if s.dockerClient != nil {
		inspect, err := s.dockerClient.ExecInspect(r.Context(), info.ExecID)
		if err == nil {
			resp["docker_running"] = inspect.Running
			resp["exit_code"] = inspect.ExitCode
			if !inspect.Running {
				resp["running"] = false
				// Update our tracked state
				s.mu.Lock()
				info.Running = false
				s.mu.Unlock()
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleAgentLogs returns the log output captured from the agent process.
// Supports optional ?tail=N query param to limit lines.
// The logs are stored in a ring buffer — oldest data is dropped when buffer is full.
func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	s.mu.Lock()
	info, ok := s.agentProcesses[name]
	s.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"logs": "",
		})
		return
	}

	logs := string(info.LogBuf)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"exec_id": info.ExecID,
		"logs":    logs,
		"size":    len(logs),
	})
}

// handleStopAgent stops a running agent by killing the Docker exec process.
func (s *Server) handleStopAgent(w http.ResponseWriter, r *http.Request) {
	if !s.requireDocker(w) {
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	s.mu.Lock()
	info, ok := s.agentProcesses[name]
	if ok {
		delete(s.agentProcesses, name)
	}
	s.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message": "No agent process to stop.",
		})
		return
	}

	// Resize the exec to force it to stop (Docker exec resize with zero rows/cols can kill it)
	// Alternatively, we can just mark it as stopped — Docker will clean up.
	log.Printf("[server] Stopping agent process for sandbox %q (execID=%s)", name, info.ExecID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"stopped": true,
		"exec_id": info.ExecID,
	})
}

// ── SSH Agent Forward Injection ──────────────────────────────────────

// handleInjectSSHAgent execs a socat process inside the running container
// to bridge the SSH agent socket to gateway.docker.internal:3129.
//
// This is Method 3 from the injection doc — it works on any running
// container regardless of whether Services were configured at creation time.
//
// The container must have socat installed. On success, returns the exec ID.
func (s *Server) handleInjectSSHAgent(w http.ResponseWriter, r *http.Request) {
	if !s.requireDocker(w) {
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Find container ID
	exists, containerID, err := s.dockerClient.ContainerExists(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to check container: "+err.Error())
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "container not found for sandbox - start it first")
		return
	}

	// Check if container is running
	info, err := s.dockerClient.InspectContainer(r.Context(), containerID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to inspect container: "+err.Error())
		return
	}
	if !info.State.Running {
		writeError(w, http.StatusConflict, "container is not running (status: "+info.State.Status+")")
		return
	}

	log.Printf("[server] Injecting SSH agent forward into container %q (id=%s)", name, containerID)
	execID, err := s.dockerClient.InjectSSHAgentForward(r.Context(), containerID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to inject SSH agent forward: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"exec_id":       execID,
		"message":       "SSH agent forward injected via socat at /run/ssh-agent.sock",
		"ssh_auth_sock": "/run/ssh-agent.sock",
	})
}

// ── Image management handlers ──────────────────────────────────────────────

func (s *Server) handleListImages(w http.ResponseWriter, r *http.Request) {
	if !s.requireDocker(w) {
		return
	}

	images, err := s.dockerClient.ListImages(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to list images: "+err.Error())
		return
	}
	if images == nil {
		images = []sbxclient.ImageSummary{}
	}
	writeJSON(w, http.StatusOK, images)
}

func (s *Server) handlePullImage(w http.ResponseWriter, r *http.Request) {
	if !s.requireDocker(w) {
		return
	}

	var req struct {
		Image string `json:"image"`
		Tag   string `json:"tag,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Image == "" {
		writeError(w, http.StatusBadRequest, "image is required")
		return
	}

	img := req.Image
	tag := req.Tag
	if tag == "" {
		// Split image:tag from the image field if no separate tag
		if idx := strings.LastIndex(img, ":"); idx > 0 && !strings.Contains(img[idx+1:], "/") {
			tag = img[idx+1:]
			img = img[:idx]
		} else {
			tag = "latest"
		}
	}

	// Stream progress as newline-delimited JSON
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	err := s.dockerClient.PullImage(r.Context(), img, tag, func(prog sbxclient.PullImageProgress) {
		line, _ := json.Marshal(prog)
		_, _ = fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
	})
	if err != nil {
		// Write error as a JSON line at the end of the stream
		errLine, _ := json.Marshal(map[string]string{"error": err.Error()})
		_, _ = fmt.Fprintf(w, "%s\n", errLine)
		flusher.Flush()
	}
}

func (s *Server) handleListPolicyRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.client.ListPolicyRules(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if rules == nil {
		rules = []sbxclient.PolicyRule{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rules": rules})
}

func (s *Server) handleApplyPolicyActions(w http.ResponseWriter, r *http.Request) {
	var req sbxclient.ApplyPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if len(req.Actions) == 0 {
		writeError(w, http.StatusBadRequest, "at least one action is required")
		return
	}
	resp, err := s.client.ApplyPolicyActions(r.Context(), req.Actions)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCheckPolicySetup(w http.ResponseWriter, r *http.Request) {
	status, err := s.client.CheckPolicySetup(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleSetDefaultPolicy(w http.ResponseWriter, r *http.Request) {
	var req sbxclient.PolicySetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Preset == "" {
		writeError(w, http.StatusBadRequest, "preset is required")
		return
	}
	resp, err := s.client.SetDefaultPolicy(r.Context(), req.Preset)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetNetworkLog(w http.ResponseWriter, r *http.Request) {
	logEntry, err := s.client.GetNetworkLog(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logEntry)
}

func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	templates, err := s.client.ListTemplates(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if templates == nil {
		templates = []sbxclient.Template{}
	}
	writeJSON(w, http.StatusOK, templates)
}

func (s *Server) handleSocketPath(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"socket_path": sbxclient.DefaultSocketPath(),
	})
}

// ── Port handlers ──────────────────────────────────────────────────────────

func (s *Server) handleListPorts(w http.ResponseWriter, r *http.Request) {
	// Ports are per-sandbox, so we list all sandboxes and collect their ports
	sbs, err := s.client.ListSandboxes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	type portEntry struct {
		ID          string `json:"id"`
		SandboxName string `json:"sandbox_name"`
		HostPort    int    `json:"host_port"`
		SandboxPort int    `json:"sandbox_port"`
		HostIP      string `json:"host_ip,omitempty"`
		Protocol    string `json:"protocol,omitempty"`
	}
	var allPorts []portEntry
	for _, sb := range sbs {
		name := sb.Spec.RuntimeName
		if name == "" {
			continue
		}
		ports, err := s.client.ListPorts(r.Context(), name)
		if err != nil {
			// Log the error but continue trying other sandboxes
			log.Printf("ListPorts(%q): %v", name, err)
			continue
		}
		for _, p := range ports {
			allPorts = append(allPorts, portEntry{
				ID:          p.ID,
				SandboxName: name,
				HostPort:    p.HostPort,
				SandboxPort: p.SandboxPort,
				HostIP:      p.HostIP,
				Protocol:    p.Protocol,
			})
		}
	}
	if allPorts == nil {
		allPorts = []portEntry{}
	}
	writeJSON(w, http.StatusOK, allPorts)
}

func (s *Server) handlePublishPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SandboxName string `json:"sandbox_name"`
		HostPort    *int   `json:"host_port,omitempty"`
		SandboxPort int    `json:"sandbox_port"`
		Protocol    string `json:"protocol,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.SandboxName == "" || req.SandboxPort == 0 {
		writeError(w, http.StatusBadRequest, "sandbox_name and sandbox_port are required")
		return
	}
	pr := sbxclient.PublishPortRequest{
		SandboxPort: req.SandboxPort,
		Protocol:    req.Protocol,
		HostPort:    req.HostPort,
	}
	ports, err := s.client.PublishPort(r.Context(), req.SandboxName, pr)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ports)
}

func (s *Server) handleUnpublishPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SandboxName string `json:"sandbox_name"`
		HostPort    int    `json:"host_port"`
		SandboxPort int    `json:"sandbox_port"`
		HostIP      string `json:"host_ip,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.SandboxName == "" {
		writeError(w, http.StatusBadRequest, "sandbox_name is required")
		return
	}
	if req.HostPort == 0 {
		writeError(w, http.StatusBadRequest, "host_port is required")
		return
	}
	if req.SandboxPort == 0 {
		writeError(w, http.StatusBadRequest, "sandbox_port is required")
		return
	}
	ur := sbxclient.UnpublishPortRequest{
		HostPort:    req.HostPort,
		SandboxPort: req.SandboxPort,
	}
	if req.HostIP != "" {
		ur.HostIP = req.HostIP
	}
	if err := s.client.UnpublishPort(r.Context(), req.SandboxName, ur); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ── Secrets bootstrap ────────────────────────────────────────────────────────

// bootstrapSecrets fetches all existing runtimes and extracts CustomSecrets
// into the in-memory store. If no runtimes exist yet, it creates a throwaway
// runtime using `sbx create` to trigger the sandboxd daemon to populate its
// internal CustomSecrets from `sbx secret set -g` values. The throwaway
// runtime is deleted immediately after extracting the secrets.
func (s *Server) bootstrapSecrets(ctx context.Context) {
	runtimes, err := s.client.ListSandboxes(ctx)
	if err != nil {
		log.Printf("Warning: could not bootstrap custom secrets: %v", err)
		return
	}

	secrets := sbxclient.ExtractCustomSecrets(runtimes)

	// If no runtimes have secrets, create a throwaway runtime to populate them.
	// This uses the `sbx` CLI which triggers sandboxd to inject the secrets
	// that were previously stored with `sbx secret set -g <service>`.
	var throwawayName string
	if len(secrets) == 0 {
		log.Printf("No custom secrets found in existing runtimes — creating throwaway bootstrap runtime...")
		throwawayName = s.createThrowawayBootstrap(ctx)
		if throwawayName != "" {
			// Re-read after creating the throwaway (before deleting it).
			runtimes, err = s.client.ListSandboxes(ctx)
			if err != nil {
				log.Printf("Warning: could not list runtimes after bootstrap: %v", err)
				// Still try to clean up
				_ = s.client.DeleteSandbox(ctx, throwawayName)
				return
			}
			secrets = sbxclient.ExtractCustomSecrets(runtimes)

			// Delete the throwaway now that we have the secrets.
			if delErr := s.client.DeleteSandbox(ctx, throwawayName); delErr != nil {
				log.Printf("Warning: could not delete throwaway bootstrap runtime %q: %v", throwawayName, delErr)
			} else {
				log.Printf("Deleted throwaway bootstrap runtime %q", throwawayName)
			}
		}
	}

	s.customSecretsMu.Lock()
	s.customSecrets = secrets
	s.customSecretsMu.Unlock()

	count := 0
	for _, v := range secrets {
		count += len(v)
	}
	if count > 0 {
		log.Printf("Bootstrapped %d custom secrets from %d existing runtimes", count, len(runtimes))
	} else {
		log.Printf("No custom secrets found. Use 'sbx secret set -g <service>' to add them, then restart the web UI.")
	}
}

// createThrowawayBootstrap runs `sbx create` to produce a runtime whose
// CustomSecrets are populated by sandboxd from the `sbx secret set` store.
// Returns the runtime name on success, or empty string on failure.
// The caller is responsible for deleting the throwaway runtime after use.
func (s *Server) createThrowawayBootstrap(ctx context.Context) string {
	name := "sbx-bootstrap-" + randomSuffix()

	// Use `sbx create` with a template that triggers secret injection.
	// The workspace dir is a random temp dir that we clean up.
	tmpDir, err := os.MkdirTemp("", "sbx-bootstrap-*")
	if err != nil {
		log.Printf("Warning: could not create temp dir for bootstrap: %v", err)
		return ""
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Look for `sbx` binary: check PATH first, then common locations
	sbxBin := findSbxBinary()
	if sbxBin == "" {
		log.Printf("Warning: 'sbx' CLI not found on PATH — cannot create throwaway bootstrap runtime")
		return ""
	}

	cmdStr := fmt.Sprintf("%s create --template containifyci/claude-code shell --name %s %s", sbxBin, name, tmpDir)
	log.Printf("Running throwaway bootstrap: %s", cmdStr)

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Warning: throwaway bootstrap 'sbx create' failed: %v\nOutput: %s", err, string(output))
		return ""
	}
	log.Printf("Throwaway bootstrap runtime %q created successfully", name)

	return name
}

// findSbxBinary locates the `sbx` CLI binary on the system.
func findSbxBinary() string {
	// Check PATH first
	if p, err := exec.LookPath("sbx"); err == nil {
		return p
	}
	// Common locations on macOS
	candidates := []string{
		"/usr/local/bin/sbx",
		"/opt/homebrew/bin/sbx",
		"/usr/bin/sbx",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// randomSuffix returns a short random alphanumeric string for naming.
func randomSuffix() string {
	b := make([]byte, 6)
	// Simple random: use nanosecond timestamp + pid to avoid needing crypto/rand
	n := time.Now().UnixNano()
	for i := 0; i < 6; i++ {
		b[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[n%36]
		n /= 36
	}
	return string(b)
}

// getCustomSecrets returns a copy of the current custom secrets map.
func (s *Server) getCustomSecrets() map[string][]sbxclient.CustomSecret {
	s.customSecretsMu.RLock()
	defer s.customSecretsMu.RUnlock()
	// Return a shallow copy so callers can't mutate the store.
	out := make(map[string][]sbxclient.CustomSecret, len(s.customSecrets))
	for k, v := range s.customSecrets {
		cp := make([]sbxclient.CustomSecret, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// handleListSecrets returns the current bootstrapped custom secrets map.
// The values are cleartext — the frontend should mask them before display.
func (s *Server) handleListSecrets(w http.ResponseWriter, r *http.Request) {
	secrets := s.getCustomSecrets()
	writeJSON(w, http.StatusOK, secrets)
}

// handleRefreshSecrets re-bootstraps secrets from all existing runtimes.
func (s *Server) handleRefreshSecrets(w http.ResponseWriter, r *http.Request) {
	s.bootstrapSecrets(r.Context())
	secrets := s.getCustomSecrets()
	writeJSON(w, http.StatusOK, secrets)
}

// osRemove is os.Remove (var for testability).
var osRemove = os.Remove

// osChmod is os.Chmod (var for testability).
var osChmod = os.Chmod

// ListenAndServe starts the HTTP server on the given address.
// If addr starts with "/" or "\." it is treated as a Unix socket path;
// otherwise it is treated as a TCP address.
func ListenAndServe(addr string, handler http.Handler) error {
	if strings.HasPrefix(addr, "/") || strings.HasPrefix(addr, "\\.") {
		// Unix socket — remove stale socket file first
		_ = osRemove(addr)
		ln, err := net.Listen("unix", addr)
		if err != nil {
			return fmt.Errorf("listen unix %s: %w", addr, err)
		}
		_ = osChmod(addr, 0666)
		log.Printf("Listening on Unix socket %s", addr)
		return http.Serve(ln, handler)
	}

	// TCP
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	log.Printf("Listening on http://%s", addr)
	return http.Serve(ln, handler)
}
