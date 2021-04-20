package prober

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

type ProberFn func(ctx context.Context, target string, config config.Module, registry *prometheus.Registry, logger log.Logger) SmtpProberResult
