package dnssec

import (
	"context"

	"github.com/miekg/dns"
	"github.com/qdm12/dns/pkg/cache"
)

type Exchange = func(ctx context.Context, request *dns.Msg) (response *dns.Msg, err error)

func wrapExchangeWithCache(exchange Exchange, cache cache.Interface) Exchange {
	return func(ctx context.Context, request *dns.Msg) (response *dns.Msg, err error) {
		response = cache.Get(request)
		if response != nil {
			return response, nil
		}

		response, err = exchange(ctx, request)
		if err != nil {
			return nil, err
		}
		cache.Add(request, response)

		return response, nil
	}
}
