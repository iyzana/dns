package dnssec

import (
	"context"
	"net"

	"github.com/miekg/dns"
	"github.com/qdm12/dns/pkg/cache"
	"github.com/qdm12/dns/pkg/cache/noop"
)

type Settings struct {
	Enabled  *bool
	Exchange Exchange
	// Cache is an optional request <-> response cache
	// to use. It defaults to a no-op implementation.
	Cache cache.Interface
}

func (s *Settings) SetDefaults() {
	if s.Enabled == nil {
		enabled := true
		s.Enabled = &enabled
	}

	if s.Exchange == nil {
		client := &dns.Client{}
		dialer := &net.Dialer{}
		s.Exchange = func(ctx context.Context, request *dns.Msg) (response *dns.Msg, err error) {
			netConn, err := dialer.DialContext(ctx, "udp", "1.1.1.1:53")
			if err != nil {
				return nil, err
			}

			dnsConn := &dns.Conn{Conn: netConn}
			response, _, err = client.ExchangeWithConn(request, dnsConn)

			_ = dnsConn.Close()

			return response, err
		}
	}

	if s.Cache == nil {
		// TODO pass down metrics?
		s.Cache = noop.New(noop.Settings{})
	}
}

func (s Settings) Validate() (err error) { return nil }
