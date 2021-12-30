package dnssec

import (
	"context"

	"github.com/miekg/dns"
)

type DialFunc func(ctx context.Context) (conn *dns.Conn, err error)
