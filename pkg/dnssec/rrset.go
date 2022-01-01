package dnssec

import (
	"context"

	"github.com/miekg/dns"
)

func fetchRRSetWithRRSig(ctx context.Context, exchange Exchange, zone string,
	recordType uint16) (rrsig *dns.RRSIG, rrset []dns.RR, err error) {
	request := newRequestWithRRSig(zone, recordType)

	response, err := exchange(ctx, request)
	if err != nil {
		return nil, nil, err
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
	return rrsig, rrset
}
