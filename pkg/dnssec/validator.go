package dnssec

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

type validator struct {
	client   *dns.Client
	exchange Exchange
}

func newValidator(settings Settings) *validator {
	settings.SetDefaults()
	return &validator{
		client:   settings.Client,
		exchange: settings.Exchange,
	}
}

func (v *validator) fetchAndValidateZone(ctx context.Context,
	zone string, qClass, qType uint16) (rrset []dns.RR, err error) {
	rrsig, rrset, err := fetchRRSetWithRRSig(ctx, v.exchange, zone, qClass, qType)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch desired RRSet and RRSig: %w", err)
	}

	delegationChain, err := newDelegationChain(ctx, v.exchange, zone, qClass)
	if err != nil {
		return nil, fmt.Errorf("cannot create delegation chain: %w", err)
	}

	err = delegationChain.verify(rrsig, rrset)
	if err != nil {
		return nil, err
	}

	return rrset, nil
}
