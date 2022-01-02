package dnssec

import (
	"context"
	"errors"
	"fmt"

	"github.com/miekg/dns"
	"github.com/qdm12/dns/internal/server"
)

var (
	ErrValidationFailedUpstream = errors.New("DNSSEC validation might had failed upstream")
)

func fetchRRSetWithRRSig(ctx context.Context, exchange server.Exchange, zone string,
	qClass, qType uint16) (rrsig *dns.RRSIG, rrset []dns.RR, err error) {
	request := newRequestWithRRSig(zone, qClass, qType)

	response, err := exchange(ctx, request)
	if err != nil {
		return nil, nil, err
	}

	if response.Rcode == dns.RcodeServerFailure {
		return nil, nil, fmt.Errorf("for %s %s %s: %w",
			zone, dns.ClassToString[qClass], dns.TypeToString[qType],
			ErrValidationFailedUpstream)
	}

	rrsig, rrset = extractRRSIGAndRRSet(response)

	return rrsig, rrset, nil
}

func extractRRSIGAndRRSet(response *dns.Msg) (rrsig *dns.RRSIG, rrset []dns.RR) {
	rrset = make([]dns.RR, 0, len(response.Answer))
	for _, rr := range response.Answer {
		rrType := rr.Header().Rrtype
		if rrType == dns.TypeRRSIG {
			rrsig = rr.(*dns.RRSIG)
			continue
		}
		rrset = append(rrset, rr)
	}

	if len(rrset) == 0 {
		rrset = nil
	}

	return rrsig, rrset
}
