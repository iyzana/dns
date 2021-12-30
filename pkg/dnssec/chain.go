package dnssec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// delegationChain is the DNSSEC chain of trust from the
// queried zone to the root (.) zone.
// See https://www.ietf.org/rfc/rfc4033.txt
type delegationChain []*signedZone

// newDelegationChain queries the RRs required for the zone validation.
// It begins the queries at the desired zone and then go
// up the delegation tree until it reaches the root zone.
// It returns a new delegation chain of signed zones where the
// first signed zone (index 0) is the child zone and the last signed
// zone is the root zone.
func newDelegationChain(ctx context.Context, dial DialFunc,
	client *dns.Client, zone string) (chain delegationChain, err error) {
	zoneParts := strings.Split(zone, ".")
	chain = make(delegationChain, len(zoneParts))

	type result struct {
		i          int
		signedZone *signedZone
		err        error
	}
	results := make(chan result)

	for i := range zoneParts {
		// 'example.com.', 'com.', '.'
		go func(i int, results chan<- result) {
			result := result{i: i}
			zoneName := dns.Fqdn(strings.Join(zoneParts[i:], "."))
			result.signedZone, result.err = queryDelegation(ctx, dial, client, zoneName)
			if result.err != nil {
				result.err = fmt.Errorf("cannot query delegation for %s: %w", zoneName, result.err)
			}
			results <- result
		}(i, results)
	}

	for range chain {
		result := <-results
		if result.err != nil && err == nil {
			err = result.err
			continue
		}
		chain[result.i] = result.signedZone
	}
	close(results)

	if err != nil {
		return nil, err
	}

	return chain, nil
}

var (
	ErrDNSKeyNotFound = errors.New("DNS Key record not found")
	ErrDNSKeyNoRRSig  = errors.New("DNS Key record has no RRSIG")
	ErrDSNotFound     = errors.New("DS record not found")
	ErrDSNoRRSig      = errors.New("DS record has no RRSIG")
)

// queryDelegation obtains the DNSKEY records and the DS
// records for a given zone. It does not query the
// (non existent) DS record for the root zone.
func queryDelegation(ctx context.Context, dial DialFunc,
	client *dns.Client, zone string) (signedZone *signedZone, err error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot dial DNS server: %w", err)
	}
	defer conn.Close()

	dnsKeyRRSig, dnsKeyRRSet, err := FetchRRSetWithRRSig(
		client, conn, zone, dns.TypeDNSKEY)
	switch {
	case err != nil:
		return nil, fmt.Errorf("cannot fetch DNS keys: %w", err)
	case len(dnsKeyRRSet) == 0:
		return nil, ErrDNSKeyNotFound
	case dnsKeyRRSig == nil:
		return nil, ErrDNSKeyNoRRSig
	}

	// TODO async both requests together

	var dsRRSig *dns.RRSIG
	var dsRRSet []dns.RR
	if zone != "." { // root zone has no DS record
		dsRRSig, dsRRSet, err = FetchRRSetWithRRSig(client, conn, zone, dns.TypeDS)
		switch {
		case err != nil:
			return nil, fmt.Errorf("cannot fetch DS records: %w", err)
		case len(dsRRSet) == 0:
			return nil, ErrDSNotFound
		case dnsKeyRRSig == nil:
			return nil, ErrDSNoRRSig
		}
	}

	err = conn.Close()
	if err != nil {
		return nil, fmt.Errorf("cannot close connection: %w", err)
	}

	return newSignedZone(zone, dnsKeyRRSig, dsRRSig, dnsKeyRRSet, dsRRSet), nil
}

var (
	ErrRRSigAbsent     = errors.New("RRSig is absent")
	ErrRRSetValidation = errors.New("RRSet validation failed")
)

// verify uses the zone data in the signed zone and its parent signed zones
// to validate the DNSSEC chain of trust.
// It starts the verification in the RRSet supplied as parameter (verifies
// the RRSIG on the answer RRs), and, assuming a signature is correct and
// valid, it walks through the linked list of signed zones checking the RRSIGs on
// the DNSKEY and DS resource record sets, as well as correctness of each
// delegation using the lower level methods in signedZone.
func (dc delegationChain) verify(rrsig *dns.RRSIG, rrset []dns.RR) error {
	if rrsig == nil {
		return ErrRRSigAbsent
	}

	signedZone := dc[0] // child desired zone

	// Verify desired RRSet
	err := signedZone.verifyRRSIG(rrsig, rrset)
	if err != nil {
		return fmt.Errorf("for zone %s and RRSIG key tag %d: %w",
			signedZone.zone, rrsig.KeyTag, err)
	}

	for i, signedZone := range dc {
		// Verify DNSKEY signature
		err := signedZone.verifyRRSIG(signedZone.dnsKeyRRSig, signedZone.dnsKeyRRSet)
		if err != nil {
			return fmt.Errorf("for zone %s and RRSIG key tag %d: %w",
				signedZone.zone, signedZone.dsRRSig.KeyTag, err)
		}

		if signedZone.zone == "." { // last element in chain
			err = verifyRootSignedZone(signedZone)
			if err != nil {
				return fmt.Errorf("failed validating root zone: %w", err)
			}

			break
		}

		// Verify DS signature with parent zone DNSKEY
		parentSignedZone := dc[i+1]
		err = parentSignedZone.verifyRRSIG(signedZone.dsRRSig, signedZone.dsRRSet)
		if err != nil {
			return fmt.Errorf("for zone %s and RRSIG key tag %d: %w",
				signedZone.zone, signedZone.dsRRSig.KeyTag, ErrRRSetValidation)
		}

		// Verify DS hash
		err = signedZone.verifyDSRRSet()
		if err != nil {
			return err
		}
	}

	return nil
}
