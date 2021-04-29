package prober

import (
	"bytes"
	"context"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

type ProbeResult struct {
	// Commands contains all smtp commands sent/received by the mail server
	Commands *bytes.Buffer
	Success  bool
	Subject  string
}

func (s *ProbeResult) Write(p []byte) (int, error) {
	if strings.HasPrefix(string(p), "AUTH PLAIN") {
		s.Commands.Write([]byte("AUTH PLAIN <secret>\r\n"))
	} else {
		s.Commands.Write(p)
	}
	return len(p), nil

}

func (s *ProbeResult) String() string {
	return s.Commands.String()
}

type ProberFn func(ctx context.Context, target string, config config.Module, registry *prometheus.Registry, logger log.Logger) ProbeResult
