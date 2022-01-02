package dnssec

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

type Settings struct {
	Enabled  *bool
	Client   *dns.Client
	Exchange Exchange
}

func (s *Settings) SetDefaults() {
	if s.Enabled == nil {
		enabled := true
		s.Enabled = &enabled
	}

	if s.Client == nil {
		s.Client = &dns.Client{}
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
}
