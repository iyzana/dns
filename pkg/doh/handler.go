package doh

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/qdm12/dns/internal/server"
	"github.com/qdm12/dns/pkg/dnssec"
)

func newDNSHandler(ctx context.Context, settings ServerSettings) (
	h dns.Handler, err error) {
	dial, err := newDoHDial(settings.Resolver)
	if err != nil {
		return nil, fmt.Errorf("cannot create DoH dial: %w", err)
	}

	exchange := server.NewExchange("DoH", dial, settings.Logger)
	exchange = dnssec.WrapDNSExchange(exchange, settings.DNSSEC)

	return server.New(ctx, exchange, settings.Filter,
		settings.Cache, settings.Logger), nil
}
