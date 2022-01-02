package dnssec

import (
	"errors"
	"time"

	"github.com/miekg/dns"
)

func newRequestWithRRSig(zone string, qClass, qType uint16) (request *dns.Msg) {
	request = &dns.Msg{
		Question: []dns.Question{{
			Name:   zone,
			Qtype:  qType,
			Qclass: qClass,
		}},
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
	}
	const maxUDPSize = 4096
	const doEdns0 = true
	request.SetEdns0(maxUDPSize, doEdns0)
	return request
}

var (
	ErrRRSigExpired = errors.New("RRSIG has expired")
)

func validateRRSet(rrset []dns.RR, rrsig *dns.RRSIG,
	dnsKey *dns.DNSKEY) (err error) {
	if !rrsig.ValidityPeriod(time.Now()) {
		return ErrRRSigExpired
	}

	if err := rrsig.Verify(dnsKey, rrset); err != nil {
		return err
	}

	return nil
}
