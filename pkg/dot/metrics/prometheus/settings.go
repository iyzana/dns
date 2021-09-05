package prometheus

import (
	prom "github.com/qdm12/dns/pkg/metrics/prometheus"
	middleware "github.com/qdm12/dns/pkg/middlewares/metrics"
	middlewarenoop "github.com/qdm12/dns/pkg/middlewares/metrics/noop"
)

type Settings struct {
	// Prometheus defines common Prometheus settings.
	Prometheus prom.Settings
	// MiddlewareMetrics is the metrics interface for the
	// DNS middleware. It defaults to a No-op implementation.
	MiddlewareMetrics middleware.Interface
}

func (s *Settings) setDefaults() {
	s.Prometheus.SetDefaults()

	if s.MiddlewareMetrics == nil {
		s.MiddlewareMetrics = middlewarenoop.New()
	}
}