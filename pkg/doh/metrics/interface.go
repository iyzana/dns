package metrics

import (
	"github.com/qdm12/dns/pkg/doh/metrics/noop"
	"github.com/qdm12/dns/pkg/doh/metrics/prometheus"
	dotmetrics "github.com/qdm12/dns/pkg/dot/metrics"
	middleware "github.com/qdm12/dns/pkg/middlewares/metrics"
)

var (
	_ Interface = (*prometheus.Metrics)(nil)
	_ Interface = (*noop.Metrics)(nil)
)

//go:generate mockgen -destination=mock_$GOPACKAGE/$GOFILE . Interface

type Interface interface {
	DialMetrics
	middleware.Interface
}

type DialMetrics interface {
	DoHDialMetrics
	dotmetrics.DoTDialMetrics
	dotmetrics.DNSDialMetrics
}

type DoHDialMetrics interface {
	DoHDialURLInc(url string)
}
