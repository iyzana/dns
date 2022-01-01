package dnssec

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

type Validator struct {
	client   *dns.Client
	exchange Exchange
}

func NewValidator(settings Settings) *Validator {
	settings.SetDefaults()
	return &Validator{
		client:   settings.Client,
		exchange: settings.Exchange,
	}
}

func (v *Validator) FetchAndValidate(ctx context.Context,
	zone string, t uint16) (rrset []dns.RR, err error) {
	rrsig, rrset, err := fetchRRSetWithRRSig(ctx, v.exchange, zone, t)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch desired RRSet and RRSig: %w", err)
	}

	delegationChain, err := newDelegationChain(ctx, v.exchange, zone)
	if err != nil {
		return nil, fmt.Errorf("cannot create delegation chain: %w", err)
	}

	err = delegationChain.verify(rrsig, rrset)
	if err != nil {
		return nil, err
	}

	return rrset, nil
}
