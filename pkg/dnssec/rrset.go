package dnssec

import (
	"github.com/miekg/dns"
)

type FetchFunc func(request *dns.Msg) (response *dns.Msg, err error)

func FetchRRSetWithRRSig(client *dns.Client, conn *dns.Conn,
	zone string, recordType uint16) (rrsig *dns.RRSIG,
	rrset []dns.RR, err error) {
	request := newRequestWithRRSig(zone, recordType)

	response, _, err := client.ExchangeWithConn(request, conn)
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
