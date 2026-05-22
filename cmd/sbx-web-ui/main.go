// Command sbx-web-ui starts an HTTP server that provides a web UI for managing
// Docker Sandboxes (sandboxd). It communicates with sandboxd over its Unix
// domain socket.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	sbxclient "github.com/frankittermann/sbx-web-ui/client"
	"github.com/frankittermann/sbx-web-ui/server"
)

func main() {
	addr := flag.String("addr", ":8080", "TCP address or Unix socket path to listen on")
	sock := flag.String("socket", "", "sandboxd Unix socket path (default: auto-detect per OS)")
	user := flag.String("user", "", "Basic auth username (enables auth when set)")
	pass := flag.String("pass", "", "Basic auth password (enables auth when set)")
	flag.Parse()

	socketPath := *sock
	if socketPath == "" {
		socketPath = sbxclient.DefaultSocketPath()
	}
	if socketPath == "" {
		fmt.Fprintf(os.Stderr, "error: could not determine sandboxd socket path for this OS\n")
		fmt.Fprintf(os.Stderr, "  Use --socket to specify the path manually.\n")
		os.Exit(1)
	}

	// Check socket exists
	if _, err := os.Stat(socketPath); err != nil {
		log.Printf("Warning: sandboxd socket not found at %s: %v", socketPath, err)
		log.Printf("  The server will start, but API calls will fail until the socket is available.")
	}

	// Create sandboxd client with Unix socket transport
	hc := &http.Client{
		Transport: sbxclient.UnixSocketDialer(socketPath),
	}
	c := sbxclient.NewClient("http://localhost", sbxclient.WithHTTPClient(hc))

	// Verify connection on startup (best-effort)
	if h, err := c.GetDaemonHealth(context.Background()); err == nil {
		log.Printf("Connected to sandboxd: %s (API v%s, status: %s)",
			h.Version, h.APIVersion, h.Status)
	} else {
		log.Printf("Note: sandboxd health check failed: %v (will retry on each request)", err)
	}

	// Create the web server with embedded static files
	var creds *server.Credentials
	if *user != "" || *pass != "" {
		if *user == "" || *pass == "" {
			fmt.Fprintf(os.Stderr, "error: --user and --pass must be used together\n")
			os.Exit(1)
		}
		creds = &server.Credentials{Username: *user, Password: *pass}
	}

	// Create Docker client for container operations (best-effort)
	dockerSock := sbxclient.DetectDockerSocket()
	var dc *sbxclient.DockerClient
	if info, err := os.Stat(dockerSock); err == nil && info.Mode()&os.ModeSocket != 0 {
		dc = sbxclient.NewDockerClient(dockerSock, "v1.53")
		log.Printf("Docker Engine socket detected at %s", dockerSock)
	} else {
		log.Printf("Warning: Docker Engine socket not found at %s; container operations disabled", dockerSock)
	}

	srv := server.New(c, dc, server.StaticFS(), creds)

	// Start listening
	go func() {
		log.Printf("Starting sbx-web-ui on %s", *addr)
		if err := server.ListenAndServe(*addr, srv); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Wait for signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal %v, shutting down...", sig)
}
