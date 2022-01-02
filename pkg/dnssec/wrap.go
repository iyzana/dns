package dnssec

import (
	"context"

	"github.com/miekg/dns"
)

func WrapDNSExchange(exchange Exchange, settings Settings) Exchange {
	if !*settings.Enabled {
		return exchange
	}

	settings.Exchange = exchange
	validator := newValidator(settings)

	return func(ctx context.Context, request *dns.Msg) (response *dns.Msg, err error) {
		return validator.exchangeAndValidate(ctx, request)
	}
}
