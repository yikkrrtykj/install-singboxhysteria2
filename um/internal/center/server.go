package center

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yikkrrtykj/install-singboxhysteria2/um/internal/schema"
)

// Server is one center instance: an isolated ingest listener for the four
// frozen node endpoints and an isolated admin listener. It owns no database,
// signing key, nonce, sequence or replay state; every authenticated decision is
// delegated to the injected Service.
type Server struct {
	cfg     Config
	svc     Service
	schemas *schema.Set
	limiter *rateLimiter

	ingest http.Handler
	admin  http.Handler

	mu           sync.Mutex
	started      bool
	closed       bool
	shuttingDown atomic.Bool
	ingestLn     net.Listener
	adminLn      net.Listener
	ingestSrv    *http.Server
	adminSrv     *http.Server
	ingestAddr   string
	adminAddr    string
}

// NewServer validates the configuration, loads and prevalidates the frozen
// contract schema set, and constructs the two isolated HTTP handlers. It does
// not open listeners, the database, or any store. A nil Service is rejected so
// a misconfigured center fails at construction.
func NewServer(cfg Config, svc Service) (*Server, error) {
	if svc == nil {
		return nil, errors.New("center: Service is required")
	}
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	schemas, err := cfg.LoadContracts()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:     cfg,
		svc:     svc,
		schemas: schemas,
		limiter: newRateLimiter(cfg.RateLimitPerSecond, cfg.RateLimitBurst, cfg.Now),
	}
	s.ingest = http.HandlerFunc(s.serveIngest)
	s.admin = http.HandlerFunc(s.serveAdmin)
	return s, nil
}

// Handler returns the ingest-plane handler. It serves exactly the four
// /v1/agent/* POST endpoints and nothing else.
func (s *Server) Handler() http.Handler { return s.ingest }

// AdminHandler returns the admin-plane handler. It serves only GET
// /api/health; it deliberately has no /v1/agent/* routes.
func (s *Server) AdminHandler() http.Handler { return s.admin }

// Start binds both listeners and starts serving. Addresses of the form
// "127.0.0.1:0" bind an ephemeral port; IngestAddr/AdminAddr report the actual
// addresses afterwards. If the second bind fails the first listener is closed.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("center: server is closed")
	}
	if s.started {
		return errors.New("center: server is already started")
	}
	ingestLn, err := net.Listen("tcp", s.cfg.IngestAddr)
	if err != nil {
		return err
	}
	adminLn, err := net.Listen("tcp", s.cfg.AdminAddr)
	if err != nil {
		_ = ingestLn.Close()
		return err
	}
	s.ingestLn, s.adminLn = ingestLn, adminLn
	s.ingestAddr = ingestLn.Addr().String()
	s.adminAddr = adminLn.Addr().String()
	s.ingestSrv = newHTTPServer(s.ingest)
	s.adminSrv = newHTTPServer(s.admin)
	s.started = true
	go func() { _ = s.ingestSrv.Serve(s.ingestLn) }()
	go func() { _ = s.adminSrv.Serve(s.adminLn) }()
	return nil
}

// IngestAddr reports the actual ingest listener address after Start, and the
// configured address before Start.
func (s *Server) IngestAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ingestAddr != "" {
		return s.ingestAddr
	}
	return s.cfg.IngestAddr
}

// AdminAddr reports the actual admin listener address after Start, and the
// configured address before Start.
func (s *Server) AdminAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adminAddr != "" {
		return s.adminAddr
	}
	return s.cfg.AdminAddr
}

// Shutdown gracefully stops both listeners and waits for in-flight handlers
// until ctx expires. It is safe to call more than once.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shuttingDown.Store(true)
	s.mu.Lock()
	started := s.started
	ingestSrv, adminSrv := s.ingestSrv, s.adminSrv
	s.mu.Unlock()
	if !started {
		return nil
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	for _, srv := range []*http.Server{ingestSrv, adminSrv} {
		if srv == nil {
			continue
		}
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			if err := srv.Shutdown(ctx); err != nil {
				errCh <- err
			}
		}(srv)
	}
	wg.Wait()
	close(errCh)
	var first error
	for err := range errCh {
		if first == nil {
			first = err
		}
	}
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return first
}

// Close immediately closes both listeners and any active connections. It is
// safe to call more than once or after Shutdown.
func (s *Server) Close() error {
	s.shuttingDown.Store(true)
	s.mu.Lock()
	started := s.started
	ingestSrv, adminSrv := s.ingestSrv, s.adminSrv
	ingestLn, adminLn := s.ingestLn, s.adminLn
	s.closed = true
	s.mu.Unlock()
	var first error
	if started {
		for _, srv := range []*http.Server{ingestSrv, adminSrv} {
			if srv == nil {
				continue
			}
			if err := srv.Close(); err != nil && first == nil {
				first = err
			}
		}
	}
	for _, ln := range []net.Listener{ingestLn, adminLn} {
		if ln == nil {
			continue
		}
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) && first == nil {
			first = err
		}
	}
	return first
}

// newHTTPServer returns the frozen transport timeouts for both planes:
// header 5 s, request read 10 s, response write 10 s, keep-alive idle 60 s.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// serveAdmin is the whole admin plane. It shares no route or handler state
// with the ingest plane: node paths are simply unknown here.
func (s *Server) serveAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/health" {
		s.writeError(w, NewAPIError(http.StatusNotFound, "endpoint_not_found", false), 0)
		return
	}
	if r.Method != http.MethodGet {
		s.writeError(w, NewAPIError(http.StatusMethodNotAllowed, "method_not_allowed", false), 0)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true,"service":"um-center"}`))
}

// nowUnix is the boundary clock used for server_time in boundary-generated
// bodies. It never returns a negative value (error.schema.json minimum is 0).
func (s *Server) nowUnix() int64 {
	now := s.cfg.Now().Unix()
	if now < 0 {
		return 0
	}
	return now
}
