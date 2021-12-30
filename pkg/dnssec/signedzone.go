package dnssec

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

type signedZone struct {
	zone           string
	dnsKeyRRSig    *dns.RRSIG
	dnsKeyRRSet    []dns.RR
	dsRRSig        *dns.RRSIG
	dsRRSet        []dns.RR
	keyTagToDNSKey map[uint16]*dns.DNSKEY
}

func dnsKeyRRSetToMap(rrset []dns.RR) (keyTagToDNSKey map[uint16]*dns.DNSKEY) {
	keyTagToDNSKey = make(map[uint16]*dns.DNSKEY, len(rrset))
	for _, rr := range rrset {
		dnsKey := rr.(*dns.DNSKEY)
		keyTagToDNSKey[dnsKey.KeyTag()] = dnsKey
	}
	return keyTagToDNSKey
}

var (
	ErrDNSKeyNotFound = errors.New("DNS Key record not found")
)

func (sz *signedZone) verifyRRSIG(rrsig *dns.RRSIG, rrset []dns.RR) (err error) {
	keyTag := rrsig.KeyTag
	dnsKey, ok := sz.keyTagToDNSKey[keyTag]
	if !ok {
		return ErrDNSKeyNotFound
	}

	return validateRRSet(rrset, rrsig, dnsKey)
}

// verifyDSRRSet validates the digests of each DS records
// against the DNS key's KSK (key signing key) digests.
func (sz *signedZone) verifyDSRRSet() (err error) {
	for _, rr := range sz.dsRRSet {
		ds := rr.(*dns.DS)
		err = sz.verifyDS(ds)
		if err != nil {
			return fmt.Errorf("for DS with key tag %d: %w",
				ds.KeyTag, err)
		}
	}
	return nil
}

// verifyDSRRSet validates the digests of each DS records
// against the DNS key's KSK (key signing key) digests.
func (sz *signedZone) verifyDS(ds *dns.DS) (err error) {
	dnsKey, ok := sz.keyTagToDNSKey[ds.KeyTag]
	if !ok {
		return ErrDNSKeyNotFound
	}

	return verifyDS(ds, dnsKey)
}

// TODO NSEC
