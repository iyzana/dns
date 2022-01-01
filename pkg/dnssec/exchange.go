package dnssec

import (
	"context"

	"github.com/miekg/dns"
)

type Exchange func(ctx context.Context, request *dns.Msg) (response *dns.Msg, err error)
