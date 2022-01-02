package doh

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/qdm12/dns/internal/server"
)

func newDNSHandler(ctx context.Context, settings ServerSettings) (
	h dns.Handler, err error) {
	client := &dns.Client{}
	dial, err := newDoHDial(settings.Resolver)
	if err != nil {
		return nil, fmt.Errorf("cannot create DoH dial: %w", err)
	}

	exchange := makeDNSExchange(client, dial, settings.Logger)

	return server.New(ctx, exchange, settings.Filter,
		settings.Cache, settings.Logger), nil
}
