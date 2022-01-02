package dnssec

import (
	"context"

	"github.com/miekg/dns"
	"github.com/qdm12/dns/internal/server"
)

func WrapDNSExchange(exchange server.Exchange, settings Settings) server.Exchange {
	settings.SetDefaults()

	if !*settings.Enabled {
		return exchange
	}

	validator := newValidator(exchange)

	return func(ctx context.Context, request *dns.Msg) (response *dns.Msg, err error) {
		return validator.exchangeAndValidate(ctx, request)
	}
}
