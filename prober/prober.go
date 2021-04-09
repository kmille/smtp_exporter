package prober

import (
	"context"

	"github.com/go-kit/kit/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/kmille/smtp_exporter/config"
)

type ProberFn func(ctx context.Context, target string, config config.Module, registry *prometheus.Registry, logger log.Logger) bool
