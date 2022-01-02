package doh

import (
	"testing"
	"time"

	cache "github.com/qdm12/dns/pkg/cache/noop"
	"github.com/qdm12/dns/pkg/dnssec"
	metrics "github.com/qdm12/dns/pkg/doh/metrics/noop"
	"github.com/qdm12/dns/pkg/filter/mapfilter"
	log "github.com/qdm12/dns/pkg/log/noop"
	middlewarelog "github.com/qdm12/dns/pkg/middlewares/log"
	"github.com/stretchr/testify/assert"
)

func Test_ServerSettings_SetDefaults(t *testing.T) {
	t.Parallel()

	cache := cache.New(cache.Settings{})
	filter := mapfilter.New(mapfilter.Settings{})
	metrics := metrics.New()
	logger := log.New()

	s := ServerSettings{
		Cache:   cache,
		Filter:  filter,
		Metrics: metrics,
		Logger:  logger,
		Resolver: ResolverSettings{
			Warner:  logger,
			Metrics: metrics,
		},
	}
	s.SetDefaults()

	// Check this otherwise things will blow up if no option is passed.
	assert.GreaterOrEqual(t, len(s.Resolver.DoHProviders), 1)
	assert.GreaterOrEqual(t, len(s.Resolver.SelfDNS.DoTProviders), 1)
	assert.Empty(t, s.Resolver.SelfDNS.DNSProviders)
	assert.GreaterOrEqual(t, int64(s.Resolver.Timeout), int64(time.Millisecond))

	boolPtr := func(b bool) *bool { return &b }

	expectedSettings := ServerSettings{
		Cache:   cache,
		Filter:  filter,
		Metrics: metrics,
		Logger:  logger,
		LogMiddleware: middlewarelog.Settings{
			Format:     "console",
			LoggerType: "noop",
		},
		Resolver: ResolverSettings{
			DoHProviders: []string{"cloudflare"},
			SelfDNS: SelfDNS{
				DoTProviders: []string{"cloudflare"},
				Timeout:      5 * time.Second,
				IPv6:         boolPtr(false),
			},
			Timeout: 5 * time.Second,
			Warner:  logger,
			Metrics: metrics,
		},
		DNSSEC: dnssec.Settings{
			Enabled: boolPtr(true),
			Cache:   cache,
		},
		Address: ":53",
	}

	// Clear exchange since it's not predictable from here
	s.DNSSEC.Exchange = nil

	assert.Equal(t, expectedSettings, s)
}

func Test_ServerSettings_String(t *testing.T) {
	t.Parallel()

	settings := ServerSettings{}
	settings.SetDefaults()

	s := settings.String()

	const expected = `DoH server settings:
├── Listening address: :53
└── DoH resolver settings:
    ├── DNS over HTTPs providers:
    |   └── Cloudflare
    ├── Internal DNS settings:
    |   ├── Query timeout: 5s
    |   ├── Connecting over: IPv4
    |   └── DNS over TLS providers:
    |       └── Cloudflare
    └── Query timeout: 5s`
	assert.Equal(t, expected, s)
}
