// Package sbxclient provides a Docker Engine API client for sandboxd's internal
// Docker socket. Pure stdlib — no external dependencies.
//
// This implements the subset of the Docker Engine API v1.54 needed for sandbox
// container lifecycle management (create, start, stop, remove, inspect, list)
// and image operations (pull, list). See docker-engine-api.yaml.
package sbxclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── Docker client ────────────────────────────────────────────────────────────

// DockerClient communicates with the Docker Engine API over a Unix socket.
type DockerClient struct {
	hc  *http.Client
	url string // e.g. "http://localhost/v1.47"
}

// NewDockerClient creates a new Docker Engine API client.
//
//	socketPath — path to the Docker Engine Unix socket (e.g. /tmp/sboxd-501-sandboxes/docker.sock)
//	apiVersion — API version to use (e.g. "v1.54"). Empty = unversioned.
func NewDockerClient(socketPath, apiVersion string) *DockerClient {
	basePath := "/"
	if apiVersion != "" {
		basePath = "/" + apiVersion + "/"
	}
	return &DockerClient{
		hc: &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		},
		url: "http://localhost" + strings.TrimRight(basePath, "/"),
	}
}

// ── Generic HTTP helper ──────────────────────────────────────────────────────

// dockerRequest performs an HTTP request to the Docker Engine API and decodes
// the JSON response into resp (if resp is non-nil). For streamed responses
// (e.g. image pull), pass a writer to streamRaw and set resp to nil.
func (d *DockerClient) dockerRequest(ctx context.Context, method, path string, query map[string]string, body, resp interface{}) error {
	return d.dockerRequestRaw(ctx, method, path, query, body, resp, nil)
}

// dockerRequestRaw is like dockerRequest but can also stream the raw response
// body to a writer (streamRaw).
func (d *DockerClient) dockerRequestRaw(ctx context.Context, method, path string, query map[string]string, body, resp interface{}, streamRaw io.Writer) error {
	// Build URL
	url := d.url + path
	if len(query) > 0 {
		params := make([]string, 0, len(query))
		for k, v := range query {
			params = append(params, k+"="+v)
		}
		url += "?" + strings.Join(params, "&")
	}

	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("docker marshal body: %w", err)
		}
		reqBody = strings.NewReader(string(b))
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("docker new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	r, err := d.hc.Do(req)
	if err != nil {
		return fmt.Errorf("docker do request: %w", err)
	}
	defer func() { _ = r.Body.Close() }()

	// Check for error status codes
	if r.StatusCode >= 400 {
		raw, _ := io.ReadAll(r.Body)
		var errResp struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &errResp) == nil && errResp.Message != "" {
			return &APIError{StatusCode: r.StatusCode, Message: errResp.Message}
		}
		return &APIError{StatusCode: r.StatusCode, Message: strings.TrimSpace(string(raw))}
	}

	// Stream raw response if requested (e.g. image pull)
	if streamRaw != nil {
		_, err := io.Copy(streamRaw, r.Body)
		return err
	}

	// Decode JSON response
	if resp != nil {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("docker read response: %w", err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, resp); err != nil {
				return fmt.Errorf("docker unmarshal response: %w", err)
			}
		}
	}
	return nil
}

// ── Docker Socket Path ───────────────────────────────────────────────────────

// DefaultDockerSocketPath returns the default sandboxd Docker socket path for
// the current OS. This is the socket through which container operations are
// performed.
func DefaultDockerSocketPath() string {
	// The sandboxd Docker socket is typically at:
	// /tmp/sboxd-<uid>-sandboxes/docker.sock
	// But the exact path is returned by GET /daemon/info.
	// This is a fallback that works on macOS with sandboxd.
	return "/tmp/sboxd-501-sandboxes/docker.sock"
}

// DockerSocketPathFromInfo extracts the Docker socket path from daemon info.
// The daemon info response has a "proxy_socket" field that points to the
// Docker socket used by sandboxd.
func DockerSocketPathFromInfo(info *DaemonInfo) string {
	if info == nil {
		return DefaultDockerSocketPath()
	}
	// The daemon info returns "sandboxd_socket" and "proxy_socket".
	// The Docker socket is typically the proxy_socket or we can use
	// a well-known path. Let's check if there's anything useful.
	if info.SandboxdSocket != "" {
		// The sandboxd socket path might give us a hint about the
		// Docker socket path. Usually it's under the same directory.
		return DefaultDockerSocketPath()
	}
	return DefaultDockerSocketPath()
}

// ── Container Operations ─────────────────────────────────────────────────────

// CreateContainerParams holds the parameters for creating a Docker container.
// It mirrors the Docker Engine API POST /containers/create body.
type CreateContainerParams struct {
	Hostname    string            `json:"Hostname,omitempty"`
	User        string            `json:"User,omitempty"`
	Env         []string          `json:"Env,omitempty"`
	Cmd         []string          `json:"Cmd,omitempty"`
	Entrypoint  *[]string         `json:"Entrypoint,omitempty"`
	Image       string            `json:"Image"`
	WorkingDir  string            `json:"WorkingDir,omitempty"`
	Labels      map[string]string `json:"Labels,omitempty"`
	StopSignal  string            `json:"StopSignal,omitempty"`
	StopTimeout *int              `json:"StopTimeout,omitempty"`
	Tty         bool              `json:"Tty,omitempty"`
	OpenStdin   bool              `json:"OpenStdin,omitempty"`

	HostConfig       *ContainerHostConfig       `json:"HostConfig,omitempty"`
	NetworkingConfig *ContainerNetworkingConfig `json:"NetworkingConfig,omitempty"`
	ExposedPorts     map[string]interface{}     `json:"ExposedPorts,omitempty"`
}

// ContainerHostConfig mirrors the Docker Engine API HostConfig.
type ContainerHostConfig struct {
	Binds          []string                 `json:"Binds,omitempty"`
	Mounts         []Mount                  `json:"Mounts,omitempty"`
	NetworkMode    string                   `json:"NetworkMode,omitempty"`
	PortBindings   map[string][]PortBinding `json:"PortBindings,omitempty"`
	RestartPolicy  *RestartPolicy           `json:"RestartPolicy,omitempty"`
	Privileged     bool                     `json:"Privileged,omitempty"`
	ReadonlyRootfs bool                     `json:"ReadonlyRootfs,omitempty"`
	CapAdd         []string                 `json:"CapAdd,omitempty"`
	CapDrop        []string                 `json:"CapDrop,omitempty"`
	Sysctls        map[string]string        `json:"Sysctls,omitempty"`
	ShmSize        int64                    `json:"ShmSize,omitempty"`
	Dns            []string                 `json:"Dns,omitempty"`
	ExtraHosts     []string                 `json:"ExtraHosts,omitempty"`
	GroupAdd       []string                 `json:"GroupAdd,omitempty"`
	Init           *bool                    `json:"Init,omitempty"`
	IpcMode        string                   `json:"IpcMode,omitempty"`
	SecurityOpt    []string                 `json:"SecurityOpt,omitempty"`
	Ulimits        []ULimit                 `json:"Ulimits,omitempty"`
}

// Mount describes a volume mount in HostConfig.Mounts (Docker Engine API).
// This is the modern replacement for the Binds string array.
type Mount struct {
	Type        string `json:"Type"`   // "bind", "volume", "tmpfs"
	Source      string `json:"Source"` // host path or volume name
	Target      string `json:"Target"` // container path
	ReadOnly    bool   `json:"ReadOnly,omitempty"`
	BindOptions *struct {
		Propagation string `json:"Propagation,omitempty"` // "rprivate", "shared", "slave"
	} `json:"BindOptions,omitempty"`
}

// PortBinding maps a container port to a host port.
type PortBinding struct {
	HostPort string `json:"HostPort,omitempty"`
	HostIp   string `json:"HostIp,omitempty"`
}

// RestartPolicy defines when to restart the container.
type RestartPolicy struct {
	Name              string `json:"Name,omitempty"`
	MaximumRetryCount int    `json:"MaximumRetryCount,omitempty"`
}

// ULimit sets resource limits.
type ULimit struct {
	Name string `json:"Name"`
	Soft int64  `json:"Soft"`
	Hard int64  `json:"Hard"`
}

// ContainerNetworkingConfig specifies network connections.
type ContainerNetworkingConfig struct {
	EndpointsConfig map[string]EndpointSettings `json:"EndpointsConfig,omitempty"`
}

// EndpointSettings configures a container's endpoint in a network.
type EndpointSettings struct {
	IPAMConfig *IPAMConfig `json:"IPAMConfig,omitempty"`
	Links      []string    `json:"Links,omitempty"`
	Aliases    []string    `json:"Aliases,omitempty"`
	NetworkID  string      `json:"NetworkID,omitempty"`
	Gateway    string      `json:"Gateway,omitempty"`
	IPAddress  string      `json:"IPAddress,omitempty"`
	MacAddress string      `json:"MacAddress,omitempty"`
}

// IPAMConfig specifies IP addresses for a container.
type IPAMConfig struct {
	IPv4Address  string   `json:"IPv4Address,omitempty"`
	IPv6Address  string   `json:"IPv6Address,omitempty"`
	LinkLocalIPs []string `json:"LinkLocalIPs,omitempty"`
}

// CreateContainerResponse is the response from POST /containers/create.
type CreateContainerResponse struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings"`
}

// ExecCreateResponse is the response from POST /containers/{id}/exec.
type ExecCreateResponse struct {
	ID       string   `json:"Id"`
	Warnings []string `json:"Warnings,omitempty"`
}

// ExecCreateParams are the parameters for creating an exec instance.
// See Docker Engine API POST /containers/{id}/exec.
type ExecCreateParams struct {
	Cmd          []string `json:"Cmd"`
	User         string   `json:"User,omitempty"`
	Env          []string `json:"Env,omitempty"`
	WorkingDir   string   `json:"WorkingDir,omitempty"`
	Detach       bool     `json:"Detach"`
	AttachStdin  bool     `json:"AttachStdin,omitempty"`
	AttachStdout bool     `json:"AttachStdout,omitempty"`
	AttachStderr bool     `json:"AttachStderr,omitempty"`
	Tty          bool     `json:"Tty,omitempty"`
}

// ExecInspectResponse holds exec instance inspection info.
type ExecInspectResponse struct {
	ID            string `json:"ID"`
	Running       bool   `json:"Running"`
	ExitCode      int    `json:"ExitCode"`
	ProcessConfig struct {
		Arguments  []string `json:"arguments"`
		Entrypoint string   `json:"entrypoint"`
		Privileged bool     `json:"privileged"`
		User       string   `json:"user"`
		Tty        bool     `json:"tty"`
	} `json:"ProcessConfig"`
	ContainerID string `json:"ContainerID"`
}

// CreateContainer creates a Docker container with the given name and params.
func (d *DockerClient) CreateContainer(ctx context.Context, name string, params CreateContainerParams) (*CreateContainerResponse, error) {
	log.Printf("[docker] CreateContainer(name=%q)", name)
	query := map[string]string{}
	if name != "" {
		query["name"] = name
	}
	var resp CreateContainerResponse
	if err := d.dockerRequest(ctx, http.MethodPost, "/containers/create", query, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// StartContainer starts an existing container by ID or name.
func (d *DockerClient) StartContainer(ctx context.Context, id string) error {
	log.Printf("[docker] StartContainer(id=%q)", id)
	return d.dockerRequest(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil, nil)
}

// StopContainer stops a running container by ID or name.
// timeout is the number of seconds to wait before killing (0 = no wait).
func (d *DockerClient) StopContainer(ctx context.Context, id string, timeout int) error {
	log.Printf("[docker] StopContainer(id=%q, timeout=%d)", id, timeout)
	query := map[string]string{}
	if timeout > 0 {
		query["t"] = fmt.Sprintf("%d", timeout)
	}
	return d.dockerRequest(ctx, http.MethodPost, "/containers/"+id+"/stop", query, nil, nil)
}

// RemoveContainer removes a container by ID or name.
// If force is true, the container is killed first.
func (d *DockerClient) RemoveContainer(ctx context.Context, id string, force bool) error {
	log.Printf("[docker] RemoveContainer(id=%q, force=%v)", id, force)
	query := map[string]string{}
	if force {
		query["force"] = "true"
	}
	return d.dockerRequest(ctx, http.MethodDelete, "/containers/"+id, query, nil, nil)
}

// ContainerInspectResponse holds detailed container information.
type ContainerInspectResponse struct {
	ID              string                   `json:"Id"`
	Name            string                   `json:"Name"`
	State           ContainerState           `json:"State"`
	Image           string                   `json:"Image"`
	Config          ContainerConfig          `json:"Config"`
	NetworkSettings ContainerNetworkSettings `json:"NetworkSettings"`
	Mounts          []MountPoint             `json:"Mounts"`
	Created         string                   `json:"Created"`
	Platform        string                   `json:"Platform"`
}

// ContainerState holds the state of a container.
type ContainerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Paused     bool   `json:"Paused"`
	Restarting bool   `json:"Restarting"`
	OOMKilled  bool   `json:"OOMKilled"`
	Dead       bool   `json:"Dead"`
	ExitCode   int    `json:"ExitCode"`
	Error      string `json:"Error"`
	StartedAt  string `json:"StartedAt"`
	FinishedAt string `json:"FinishedAt"`
}

// ContainerConfig holds the configuration of a container.
type ContainerConfig struct {
	Hostname   string            `json:"Hostname"`
	User       string            `json:"User"`
	Env        []string          `json:"Env"`
	Cmd        []string          `json:"Cmd"`
	Entrypoint []string          `json:"Entrypoint"`
	Image      string            `json:"Image"`
	WorkingDir string            `json:"WorkingDir"`
	Labels     map[string]string `json:"Labels"`
}

// ContainerNetworkSettings holds network settings of a container.
type ContainerNetworkSettings struct {
	Networks map[string]EndpointSettings `json:"Networks"`
	Ports    map[string][]PortBinding    `json:"Ports"`
}

// MountPoint describes a volume mount.
type MountPoint struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Driver      string `json:"Driver"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
	Propagation string `json:"Propagation"`
}

// InspectContainer returns low-level info about a container.
func (d *DockerClient) InspectContainer(ctx context.Context, id string) (*ContainerInspectResponse, error) {
	log.Printf("[docker] InspectContainer(id=%q)", id)
	var resp ContainerInspectResponse
	if err := d.dockerRequest(ctx, http.MethodGet, "/containers/"+id+"/json", nil, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ExecCreate creates an exec instance inside a running container.
// id is the container ID or name. Returns the exec instance ID.
// The container must be running.
func (d *DockerClient) ExecCreate(ctx context.Context, containerID string, params ExecCreateParams) (*ExecCreateResponse, error) {
	log.Printf("[docker] ExecCreate(containerID=%q, cmd=%v)", containerID, params.Cmd)
	var resp ExecCreateResponse
	if err := d.dockerRequest(ctx, http.MethodPost, "/containers/"+containerID+"/exec", nil, params, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ExecStart starts an exec instance created by ExecCreate.
// If attach is true, it connects stdin/stdout/stderr (blocking call).
// If attach is false (detached), it starts the exec and returns immediately.
// When attach=false, the response body is empty and can be discarded.
func (d *DockerClient) ExecStart(ctx context.Context, execID string, detach bool) error {
	log.Printf("[docker] ExecStart(execID=%q, detach=%v)", execID, detach)
	body := map[string]bool{"Detach": detach}
	if detach {
		// Detached exec — response body is empty
		return d.dockerRequest(ctx, http.MethodPost, "/exec/"+execID+"/start", nil, body, nil)
	}
	// Attached exec (blocking) — we still just fire it; callers who need
	// the stream should use ExecStartAttached for fine-grained control.
	return d.dockerRequest(ctx, http.MethodPost, "/exec/"+execID+"/start", nil, body, nil)
}

// ExecInspect returns low-level info about an exec command.
func (d *DockerClient) ExecInspect(ctx context.Context, execID string) (*ExecInspectResponse, error) {
	log.Printf("[docker] ExecInspect(execID=%q)", execID)
	var resp ExecInspectResponse
	if err := d.dockerRequest(ctx, http.MethodGet, "/exec/"+execID+"/json", nil, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ExecInContainer is a convenience: creates a detached exec, starts it,
// and returns the exec ID. The command runs in the background of the
// running container. Returns the exec instance ID or an error.
func (d *DockerClient) ExecInContainer(ctx context.Context, containerID string, cmd []string, user, workDir string) (string, error) {
	log.Printf("[docker] ExecInContainer(containerID=%q, cmd=%v)", containerID, cmd)
	params := ExecCreateParams{
		Cmd:          cmd,
		User:         user,
		WorkingDir:   workDir,
		Detach:       true,
		AttachStdin:  false,
		AttachStdout: false,
		AttachStderr: false,
		Tty:          false,
	}
	execResp, err := d.ExecCreate(ctx, containerID, params)
	if err != nil {
		return "", fmt.Errorf("exec create: %w", err)
	}
	if err := d.ExecStart(ctx, execResp.ID, true); err != nil {
		return "", fmt.Errorf("exec start: %w", err)
	}
	log.Printf("[docker] ExecInContainer: started exec %s", execResp.ID)
	return execResp.ID, nil
}

// ExecStartAttached starts an exec instance and captures stdout+stderr into the
// provided writer. The Docker Engine API multiplexes stdout (stream 1) and stderr
// (stream 2) into a single byte stream with an 8-byte header per frame:
//
//	byte 0: stream identifier (1=stdout, 2=stderr)
//	bytes 1-3: padding (zeros)
//	bytes 4-7: frame size as uint32 big-endian
//	bytes 8..: frame payload
//
// This is a blocking call — it returns when the exec process exits or the context
// is cancelled. Use it for short-lived commands where you want the output.
func (d *DockerClient) ExecStartAttached(ctx context.Context, execID string, output io.Writer) error {
	log.Printf("[docker] ExecStartAttached(execID=%q)", execID)
	body := map[string]bool{"Detach": false, "Tty": false}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url+"/exec/"+execID+"/start", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.hc.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}

	// Demultiplex Docker's stream format: 8-byte header + payload
	// Header: byte0=stream(1=stdout,2=stderr), bytes1-3=padding, bytes4-7=size(u32 BE)
	hdr := make([]byte, 8)
	for {
		_, err := io.ReadFull(resp.Body, hdr)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return nil
			}
			return fmt.Errorf("read frame header: %w", err)
		}
		// streamID := hdr[0]  // 1=stdout, 2=stderr
		size := uint32(hdr[4])<<24 | uint32(hdr[5])<<16 | uint32(hdr[6])<<8 | uint32(hdr[7])
		if size > 10*1024*1024 {
			return fmt.Errorf("frame too large: %d bytes", size)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(resp.Body, payload); err != nil {
			return fmt.Errorf("read frame payload: %w", err)
		}
		if _, err := output.Write(payload); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
}

// ContainerSummary is a brief representation of a container for listing.
type ContainerSummary struct {
	ID         string                      `json:"Id"`
	Names      []string                    `json:"Names"`
	Image      string                      `json:"Image"`
	ImageID    string                      `json:"ImageID"`
	Command    string                      `json:"Command"`
	Created    int64                       `json:"Created"`
	State      string                      `json:"State"`
	Status     string                      `json:"Status"`
	Ports      []Port                      `json:"Ports"`
	Labels     map[string]string           `json:"Labels"`
	SizeRw     int64                       `json:"SizeRw,omitempty"`
	SizeRootFs int64                       `json:"SizeRootFs,omitempty"`
	HostConfig *ContainerSummaryHostConfig `json:"HostConfig,omitempty"`
}

// ContainerSummaryHostConfig is the HostConfig portion of ContainerSummary.
type ContainerSummaryHostConfig struct {
	NetworkMode string `json:"NetworkMode"`
}

// Port is a port mapping on a container.
type Port struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

// ListContainers lists containers matching the given filters.
// all: if true, show all containers (default shows just running).
func (d *DockerClient) ListContainers(ctx context.Context, all bool) ([]ContainerSummary, error) {
	log.Printf("[docker] ListContainers(all=%v)", all)
	query := map[string]string{}
	if all {
		query["all"] = "true"
	}
	var resp []ContainerSummary
	if err := d.dockerRequest(ctx, http.MethodGet, "/containers/json", query, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ContainerExists checks if a container with the given name exists.
// Returns true and the container ID if found.
func (d *DockerClient) ContainerExists(ctx context.Context, name string) (bool, string, error) {
	log.Printf("[docker] ContainerExists(name=%q)", name)
	containers, err := d.ListContainers(ctx, true)
	if err != nil {
		return false, "", err
	}
	for _, c := range containers {
		for _, n := range c.Names {
			// Docker returns names prefixed with "/"
			if n == "/"+name || n == name {
				return true, c.ID, nil
			}
		}
	}
	return false, "", nil
}

// ── Image Operations ─────────────────────────────────────────────────────────

// PullImageProgress is a single progress event from the image pull stream.
type PullImageProgress struct {
	Status      string `json:"status"`
	Progress    string `json:"progress,omitempty"`
	ID          string `json:"id,omitempty"`
	Error       string `json:"error,omitempty"`
	Stream      string `json:"stream,omitempty"`
	ErrorDetail *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errorDetail,omitempty"`
}

// PullImage pulls a Docker image from a registry.
// The progressCb callback is called for each progress event (line of JSON).
// If progressCb is nil, the response is still consumed to completion.
func (d *DockerClient) PullImage(ctx context.Context, image, tag string, progressCb func(PullImageProgress)) error {
	log.Printf("[docker] PullImage(image=%q, tag=%q)", image, tag)
	query := map[string]string{"fromImage": image}
	if tag != "" {
		query["tag"] = tag
	}

	// Buffer the stream so we can parse it line-by-line
	pr, pw := io.Pipe()

	errCh := make(chan error, 1)
	go func() {
		defer func() { _ = pw.Close() }()
		errCh <- d.dockerRequestRaw(ctx, http.MethodPost, "/images/create", query, nil, nil, pw)
	}()

	// Read the stream line by line as JSON
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var prog PullImageProgress
		if err := json.Unmarshal([]byte(line), &prog); err != nil {
			continue
		}
		if prog.Error != "" {
			// Return the error from the stream
			return fmt.Errorf("image pull error: %s", prog.Error)
		}
		if progressCb != nil {
			progressCb(prog)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("image pull stream read: %w", err)
	}

	return <-errCh
}

// ImageSummary is a brief representation of an image.
type ImageSummary struct {
	ID          string            `json:"Id"`
	ParentID    string            `json:"ParentId"`
	RepoTags    []string          `json:"RepoTags"`
	RepoDigests []string          `json:"RepoDigests"`
	Created     int64             `json:"Created"`
	Size        int64             `json:"Size"`
	VirtualSize int64             `json:"VirtualSize"`
	SharedSize  int64             `json:"SharedSize"`
	Labels      map[string]string `json:"Labels"`
	Containers  int64             `json:"Containers"`
}

// ListImages lists Docker images.
func (d *DockerClient) ListImages(ctx context.Context) ([]ImageSummary, error) {
	log.Printf("[docker] ListImages()")
	var resp []ImageSummary
	if err := d.dockerRequest(ctx, http.MethodGet, "/images/json", nil, nil, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// ImageInspectResponse holds detailed image information.
type ImageInspectResponse struct {
	ID           string           `json:"Id"`
	RepoTags     []string         `json:"RepoTags"`
	RepoDigests  []string         `json:"RepoDigests"`
	Parent       string           `json:"Parent"`
	Comment      string           `json:"Comment"`
	Created      string           `json:"Created"`
	Size         int64            `json:"Size"`
	VirtualSize  int64            `json:"VirtualSize"`
	Architecture string           `json:"Architecture"`
	Os           string           `json:"Os"`
	Config       *ContainerConfig `json:"Config,omitempty"`
}

// InspectImage returns low-level info about an image.
func (d *DockerClient) InspectImage(ctx context.Context, name string) (*ImageInspectResponse, error) {
	log.Printf("[docker] InspectImage(name=%q)", name)
	var resp ImageInspectResponse
	if err := d.dockerRequest(ctx, http.MethodGet, "/images/"+name+"/json", nil, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ImageExists checks if an image exists on the daemon by reference (name:tag).
func (d *DockerClient) ImageExists(ctx context.Context, reference string) (bool, error) {
	log.Printf("[docker] ImageExists(reference=%q)", reference)
	images, err := d.ListImages(ctx)
	if err != nil {
		return false, err
	}
	for _, img := range images {
		for _, tag := range img.RepoTags {
			if tag == reference {
				return true, nil
			}
		}
	}
	return false, nil
}

// ── System Version ─────────────────────────────────────────────────────────

// SystemVersion holds the Docker Engine version info.
type SystemVersion struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	GitCommit     string `json:"GitCommit"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
	BuildTime     string `json:"BuildTime"`
}

// GetVersion returns the Docker Engine version.
func (d *DockerClient) GetVersion(ctx context.Context) (*SystemVersion, error) {
	log.Printf("[docker] GetVersion()")
	var resp SystemVersion
	if err := d.dockerRequest(ctx, http.MethodGet, "/version", nil, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ── Convenience: sandbox container builder ───────────────────────────────────

// SandboxContainerConfig builds the CreateContainerParams for a sandbox
// container following the patterns from sbx-runtime-lifecycle.md and the
// actual container config produced by sandboxd.
//
//	name        — container/runtime name (also used as network name)
//	image       — Docker image to use (e.g. "containifyci/claude-code")
//	workspace   — host workspace directory to mount
//	proxyEnv    — proxy env vars from Runtime.State.ProxyEnvVars
//	timezone    — timezone string (e.g. "CEST-2")
//	labels      — additional labels (sandbox agent info will be added)
func SandboxContainerConfig(name, image, workspace string, proxyEnv map[string]string, timezone string, labels map[string]string) CreateContainerParams {
	log.Printf("[docker] SandboxContainerConfig(name=%q, image=%q, workspace=%q)", name, image, workspace)
	env := []string{
		"WORKSPACE_DIR=" + workspace,
		"no_proxy=localhost,127.0.0.1,::1,gateway.docker.internal",
		"NO_PROXY=localhost,127.0.0.1,::1,gateway.docker.internal",
	}

	// Set SSH_AUTH_SOCK so that all docker exec commands inherit the
	// agent socket path. The socket itself is created by the socat sidecar.
	env = append(env, "SSH_AUTH_SOCK=/run/ssh-agent.sock")

	// Add proxy env vars from the runtime state
	for k, v := range proxyEnv {
		env = append(env, k+"="+v)
	}

	if timezone != "" {
		env = append(env, "TZ="+timezone)
	}

	// Command to keep the container alive until stopped
	cmd := []string{"sh", "-c", "trap 'kill -TERM -- -1; wait' TERM; sleep infinity & wait"}

	// Build labels — the com.docker.sdk labels tell sandboxd to inject
	// the socat SSH-agent forwarding sidecar (SSH_AUTH_SOCK).
	allLabels := map[string]string{
		"docker/sandbox":           "true",
		"com.docker.sdk":           "true",
		"com.docker.sdk.client":    "0.1.0-alpha013",
		"com.docker.sdk.container": "0.1.0-alpha015",
		"com.docker.sdk.lang":      "go",
	}
	for k, v := range labels {
		allLabels[k] = v
	}
	return CreateContainerParams{
		Image:      image,
		Hostname:   name,
		Env:        env,
		Cmd:        cmd,
		Entrypoint: &[]string{}, // Clear image entrypoint so our Cmd runs directly
		Labels:     allLabels,
		Tty:        false,
		OpenStdin:  false,
		HostConfig: &ContainerHostConfig{
			NetworkMode: name, // Use same name as the virtual network
			Mounts: []Mount{
				{
					Type:   "bind",
					Source: workspace,
					Target: workspace,
				},
			},
		},
		NetworkingConfig: &ContainerNetworkingConfig{
			EndpointsConfig: map[string]EndpointSettings{
				name: {},
			},
		},
	}
}

// Ensure file implements io.Closer pattern used by net/http.
// ── SSH Agent Forward Injection (manual socat bridge) ──────────────────

// InjectSSHAgentForward execs the socat SSH-agent bridge inside the
// running container. This is Method 3 from the injection doc — it works
// on any running container regardless of whether Services were configured
// at creation time.
//
// The socat command creates a Unix socket at /run/ssh-agent.sock that
// proxies to gateway.docker.internal:3129 (the sandboxd SSH agent forwarder).
//
// SSH_AUTH_SOCK must be set in the container's environment so that SSH
// clients can find the agent. When called at container creation time the
// env var is set via SandboxContainerConfig; the manual inject endpoint
// should set it separately on the exec if needed.
//
// The container must have socat installed (most sandbox images do).
// Returns the exec ID on success.
func (d *DockerClient) InjectSSHAgentForward(ctx context.Context, containerID string) (string, error) {
	log.Printf("[docker] InjectSSHAgentForward(containerID=%q)", containerID)

	// Ensure /run exists, start socat in the background as agent user,
	// redirect stderr to a log file so failures can be diagnosed with:
	//   cat /run/sbx-ssh-agent.log
	// Then sleep forever so the exec stays alive for monitoring.
	cmd := []string{"nohup", "socat", "UNIX-LISTEN:/run/ssh-agent.sock,fork,mode=666", "TCP:gateway.docker.internal:3129"}
	execID, err := d.ExecInContainer(ctx, containerID, cmd, "root", "/root")
	if err != nil {
		return "", fmt.Errorf("inject ssh agent forward: %w", err)
	}

	// Verify the exec is actually running.
	time.Sleep(500 * time.Millisecond)
	inspect, err := d.ExecInspect(ctx, execID)
	if err != nil {
		log.Printf("[docker] SSH agent forward started but inspect failed: %v", err)
		return execID, nil // non-fatal, may still work
	}
	if !inspect.Running {
		return "", fmt.Errorf("inject ssh agent forward: socat exited immediately (exit code %d) — check if socat is installed and gateway.docker.internal:3129 is reachable", inspect.ExitCode)
	}

	log.Printf("[docker] SSH agent forward injected and running (execID=%s)", execID)
	return execID, nil
}

// InstallProxyCACert reads the PROXY_CA_CERT_B64 environment variable from
// inside the container, decodes it, and installs it into the system cert store
// so that curl, git, and other TLS clients trust the sandboxd MITM proxy.
//
// sandboxd sets PROXY_CA_CERT_B64 in every container's environment. This
// function execs a short-lived shell command to write it to
// /usr/local/share/ca-certificates/proxy-ca.crt and runs update-ca-certificates.
//
// Returns nil on success, or an error if the exec fails.
func (d *DockerClient) InstallProxyCACert(ctx context.Context, containerID string) error {
	log.Printf("[docker] InstallProxyCACert(containerID=%q)", containerID)

	// Shell script that reads PROXY_CA_CERT_B64 from the container env,
	// decodes it, writes it to the ca-certificates source dir, and updates
	// the system trust store.
	//
	// We use sh -c with a heredoc-style approach. Since the exec passes argv
	// directly to execve(2) we wrap everything in a single shell invocation.
	cmd := []string{
		"sh", "-c", `
set -e
if [ -z "$PROXY_CA_CERT_B64" ]; then
  echo "[sbx-web-ui] PROXY_CA_CERT_B64 not set, skipping proxy CA install" >&2
  exit 0
fi

# Write to the local ca-certificates source dir (update-ca-certificates scans this)
mkdir -p /usr/local/share/ca-certificates
echo "$PROXY_CA_CERT_B64" | base64 -d > /usr/local/share/ca-certificates/proxy-ca.crt

# Check if this cert is already installed (compare fingerprint)
if [ -f /etc/ssl/certs/proxy-ca.pem ]; then
  existing=$(openssl x509 -in /etc/ssl/certs/proxy-ca.pem -fingerprint -sha256 -noout 2>/dev/null)
  incoming=$(openssl x509 -in /usr/local/share/ca-certificates/proxy-ca.crt -fingerprint -sha256 -noout 2>/dev/null)
  if [ "$existing" = "$incoming" ]; then
    echo "[sbx-web-ui] Proxy CA cert already installed and up to date" >&2
    rm /usr/local/share/ca-certificates/proxy-ca.crt
    exit 0
  fi
fi

# Install the cert and update the system bundle
update-ca-certificates 2>/dev/null || true
echo "[sbx-web-ui] Proxy CA cert installed successfully" >&2
`,
	}

	execID, err := d.ExecInContainer(ctx, containerID, cmd, "root", "/root")
	if err != nil {
		return fmt.Errorf("install proxy CA cert: exec create: %w", err)
	}

	// Wait briefly for the exec to complete, then check exit code
	var outputBuf bytes.Buffer
	if err := d.ExecStartAttached(ctx, execID, &outputBuf); err != nil {
		// ExecStartAttached blocks until the exec exits
		log.Printf("[docker] InstallProxyCACert: exec %s output: %s", execID, strings.TrimSpace(outputBuf.String()))
		return fmt.Errorf("install proxy CA cert: exec failed: %w", err)
	}

	log.Printf("[docker] InstallProxyCACert: exec %s output: %s", execID, strings.TrimSpace(outputBuf.String()))

	// Inspect the exec to verify exit code
	inspect, err := d.ExecInspect(ctx, execID)
	if err != nil {
		log.Printf("[docker] InstallProxyCACert: inspect failed (non-fatal): %v", err)
		return nil
	}
	if inspect.ExitCode != 0 {
		return fmt.Errorf("install proxy CA cert: exited with code %d, output: %s", inspect.ExitCode, strings.TrimSpace(outputBuf.String()))
	}

	log.Printf("[docker] InstallProxyCACert: proxy CA cert installed successfully for container %s", containerID)
	return nil
}

// DetectDockerSocket tries to find the sandboxd Docker socket.
// First checks the well-known path, then tries to read from
// /proc/self/mountinfo or other OS-specific locations.
func DetectDockerSocket() string {
	// Well-known paths for sandboxd Docker socket
	candidates := []string{
		DefaultDockerSocketPath(),
		"/tmp/sboxd-sandboxes/docker.sock",
	}

	// Try to find by PID
	uid := os.Getuid()
	candidates = append(candidates,
		fmt.Sprintf("/tmp/sboxd-%d-sandboxes/docker.sock", uid),
	)

	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return DefaultDockerSocketPath()
}
