package dnssec

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
)

type Validator struct {
	client *dns.Client
	dial   DialFunc
}

func NewValidator(settings Settings) *Validator {
	settings.SetDefaults()
	return &Validator{
		client: settings.Client,
		dial:   settings.Dial,
	}
}

func (v *Validator) Validate(ctx context.Context,
	zone string, t uint16) (rrset []dns.RR, err error) {
	conn, err := v.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot dial DNS server: %w", err)
	}

	rrsig, rrset, err := fetchRRSetWithRRSig(v.client, conn, zone, t)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("cannot fetch desired RRSet and RRSig: %w", err)
	}

	err = conn.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close connection: %w", err)
	}

	delegationChain, err := newDelegationChain(ctx, v.dial, v.client, zone)
	if err != nil {
		return nil, fmt.Errorf("cannot create delegation chain: %w", err)
	}

	err = delegationChain.verify(rrsig, rrset)
	if err != nil {
		return nil, err
	}

	return rrset, nil
}
