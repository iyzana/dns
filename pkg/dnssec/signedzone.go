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

func newSignedZone(zone string, dnsKeyRRSig, dsRRSig *dns.RRSIG,
	dnsKeyRRSet, dsRRSet []dns.RR) *signedZone {
	keyTagToDNSKey := make(map[uint16]*dns.DNSKEY, len(dnsKeyRRSet))
	for _, rr := range dnsKeyRRSet {
		dnsKey := rr.(*dns.DNSKEY)
		keyTagToDNSKey[dnsKey.KeyTag()] = dnsKey
	}

	return &signedZone{
		zone:           zone,
		dnsKeyRRSig:    dnsKeyRRSig,
		dnsKeyRRSet:    dnsKeyRRSet,
		dsRRSig:        dsRRSig,
		dsRRSet:        dsRRSet,
		keyTagToDNSKey: keyTagToDNSKey,
	}
}

var (
	ErrDNSKeyTagNotFound = errors.New("DNSKEY tag not found")
)

func (sz *signedZone) verifyRRSIG(rrsig *dns.RRSIG, rrset []dns.RR) (err error) {
	keyTag := rrsig.KeyTag
	dnsKey, ok := sz.keyTagToDNSKey[keyTag]
	if !ok {
		return ErrDNSKeyTagNotFound
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
