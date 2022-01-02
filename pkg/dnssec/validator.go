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

	exchange := wrapExchangeWithCache(settings.Exchange, settings.Cache)

	return &validator{
		client:   settings.Client,
		exchange: exchange,
	}
}

func (v *validator) exchangeAndValidate(ctx context.Context,
	request *dns.Msg) (response *dns.Msg, err error) {
	response = new(dns.Msg)
	response.Answer = make([]dns.RR, 0, len(request.Question))

	for _, question := range request.Question {
		rrset, err := v.fetchAndValidateZone(ctx, question.Name, question.Qclass, question.Qtype)
		if err != nil {
			return nil, fmt.Errorf("failed to validate %s %s %s: %w",
				question.Name, dns.ClassToString[question.Qclass],
				dns.TypeToString[question.Qtype], err)
		}

		response.Answer = append(response.Answer, rrset...)
	}

	return response, nil
}

func (v *validator) fetchAndValidateZone(ctx context.Context,
	zone string, qClass, qType uint16) (rrset []dns.RR, err error) {
	rrsig, rrset, err := fetchRRSetWithRRSig(ctx, v.exchange, zone, qClass, qType)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch desired RRSet and RRSig: %w", err)
	}

	if rrsig == nil {
		// Let unsigned zones through :(
		return rrset, nil
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
