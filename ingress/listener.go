package ingress

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
)

// ingressSem ограничивает количество одновременно обрабатываемых TCP-соединений
// Размер должен быть подобран с учетом доступных ресурсов RAM и CPU
var ingressSem = func() chan struct{} {
	// fallback
	limit := 512
	if v := getenvInt("RELAY_INGRESS_MAX_CONNS"); v > 0 {
		limit = v
	}
	return make(chan struct{}, limit)
}()

func getenvInt(key string) int {
	if val := os.Getenv(key); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

type Server struct {
	listener   net.Listener
	wg         sync.WaitGroup
	closeOnce  sync.Once
	closeErr   error
	acceptDone chan struct{}
}

func NewServer(addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Server{
		listener:   ln,
		acceptDone: make(chan struct{}),
	}, nil
}

func (s *Server) Serve() error {
	defer close(s.acceptDone)
	log.Println("HTTPS passthrough listening on", s.listener.Addr())

	for {
		c, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Println("accept error:", err)
			continue
		}

		select {
		case ingressSem <- struct{}{}:

		default:
			log.Printf("ingress rejected: remote=%s reason=max_connections limit=%d", c.RemoteAddr(), cap(ingressSem))
			if err := c.Close(); err != nil {
				log.Printf("close rejected ingress connection failed: remote=%s err=%v", c.RemoteAddr(), err)
			}
			continue
		}

		s.wg.Add(1)
		go func(conn net.Conn) {
			defer s.wg.Done()
			defer func() { <-ingressSem }()
			handleClientTCP(conn)
		}(c)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.StopAccepting(); err != nil {
		return err
	}

	done := make(chan struct{})
	go func() {
		<-s.acceptDone
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) StopAccepting() error {
	s.closeOnce.Do(func() {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.closeErr = err
		}
	})
	return s.closeErr
}
