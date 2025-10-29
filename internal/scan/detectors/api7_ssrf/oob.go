package api7ssrf

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type OOBServer interface {
	Start(ctx context.Context) error

	Stop() error

	// Generate a unique URL for testing
	GenerateURL(identifier string) string

	// Check if a callback was received for given identifier
	CheckCallback(identifier string, timeout time.Duration) bool

	GetBaseURL() string
}

type CallbackRecord struct {
	Identifier string
	ReceivedAt time.Time
	Method     string
	Path       string
	Headers    map[string][]string
	Body       []byte
	RemoteAddr string
}

type SimpleOOBServer struct {
	listener net.Listener
	server   *http.Server
	baseURL  string
	port     int

	mu        sync.RWMutex
	callbacks map[string]*CallbackRecord

	ready chan struct{}
}

func newSimpleOOBServer() *SimpleOOBServer {
	return &SimpleOOBServer{
		callbacks: make(map[string]*CallbackRecord),
		ready:     make(chan struct{}),
	}
}

func (s *SimpleOOBServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	s.listener = ln
	s.port = ln.Addr().(*net.TCPAddr).Port

	// 1) Choose the advertised host
	adv := os.Getenv("OOB_ADVERTISE_HOST")
	if adv == "" {
		adv = pickNonLoopbackIPv4() // falls back to 127.0.0.1 if none found
	}

	// IMPORTANT: advertise a real host/IP (never 0.0.0.0)
	s.baseURL = fmt.Sprintf("http://%s:%d", adv, s.port)

	// 2) Handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleCallback)

	// 3) HTTP server
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 0, // adjust if you want
	}

	// 4) Serve
	go func() {
		close(s.ready) // signal ready (ensure s.ready was created)
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Printf("OOB server error: %v\n", err)
		}
	}()

	<-s.ready
	fmt.Printf("[oob] listening on %s (advertised: %s)\n", ln.Addr().String(), s.baseURL)
	return nil
}

// pickNonLoopbackIPv4 returns a non-loopback IPv4 if possible, else "127.0.0.1".
func pickNonLoopbackIPv4() string {
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if (ifc.Flags & net.FlagUp) == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				ip := ipnet.IP
				if ip == nil || ip.IsLoopback() {
					continue
				}
				ip4 := ip.To4()
				if ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

func (s *SimpleOOBServer) Stop() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *SimpleOOBServer) GetBaseURL() string {
	return s.baseURL
}

func (s *SimpleOOBServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Extract identifier from path
	identifier := r.URL.Path
	if len(identifier) > 0 && identifier[0] == '/' {
		identifier = identifier[1:] // Remove leading slash
	}

	// Read body
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))

	// Store callback
	record := &CallbackRecord{
		Identifier: identifier,
		ReceivedAt: time.Now(),
		Method:     r.Method,
		Path:       r.URL.Path,
		Headers:    r.Header,
		Body:       body,
		RemoteAddr: r.RemoteAddr,
	}

	s.mu.Lock()
	s.callbacks[identifier] = record
	s.mu.Unlock()

	// Respond with 200 OK
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *SimpleOOBServer) GenerateURL(identifier string) string {
	return fmt.Sprintf("%s/%s", s.baseURL, identifier)
}

func (s *SimpleOOBServer) CheckCallback(identifier string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	// Poll for callback
	for time.Now().Before(deadline) {
		s.mu.RLock()
		_, exists := s.callbacks[identifier]
		s.mu.RUnlock()

		if exists {
			return true
		}

		// Wait a bit before checking again
		time.Sleep(100 * time.Millisecond)
	}

	return false
}

// GetCallbackRecord retrieves the callback record for an identifier
func (s *SimpleOOBServer) GetCallbackRecord(identifier string) *CallbackRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.callbacks[identifier]
}
