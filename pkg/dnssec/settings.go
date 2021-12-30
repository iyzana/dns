package dnssec

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

type Settings struct {
	Client *dns.Client
	Dial   DialFunc
}

func (s *Settings) SetDefaults() {
	if s.Client == nil {
		s.Client = &dns.Client{}
	}

	if s.Dial == nil {
		dialer := &net.Dialer{}
		s.Dial = func(ctx context.Context) (conn *dns.Conn, err error) {
			netConn, err := dialer.DialContext(ctx, "udp", "1.1.1.1:53")
			if err != nil {
				return nil, err
			}
			return &dns.Conn{Conn: netConn}, nil
		}
	}
}
