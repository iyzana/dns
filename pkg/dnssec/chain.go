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

// queryDelegation obtains the DNSKEY records and the DS
// records for a given zone. It does not query the
// (non existent) DS record for the root zone.
func queryDelegation(ctx context.Context, dial DialFunc,
	client *dns.Client, zone string) (sz *signedZone, err error) {
	if zone == "." {
		// Only query DNSKEY since root zone has no DS record.
		rrsig, rrset, err := queryDNSKey(ctx, dial, client, zone)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch DNSKEY records: %w", err)
		}
		return &signedZone{
			zone:           zone,
			dnsKeyRRSig:    rrsig,
			dnsKeyRRSet:    rrset,
			keyTagToDNSKey: dnsKeyRRSetToMap(rrset),
		}, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		t     uint16
		rrsig *dns.RRSIG
		rrset []dns.RR
		err   error
	}
	results := make(chan result)

	go func(ctx context.Context, dial DialFunc, zone string, results chan<- result) {
		result := result{t: dns.TypeDNSKEY}
		result.rrsig, result.rrset, result.err = queryDNSKey(ctx, dial, client, zone)
		if result.err != nil {
			result.err = fmt.Errorf("cannot fetch DNSKEY records: %w", result.err)
		}
		results <- result
	}(ctx, dial, zone, results)

	go func(ctx context.Context, dial DialFunc, zone string, results chan<- result) {
		result := result{t: dns.TypeDS}
		result.rrsig, result.rrset, result.err = queryDS(ctx, dial, client, zone)
		if result.err != nil {
			result.err = fmt.Errorf("cannot fetch DS records: %w", result.err)
		}
		results <- result
	}(ctx, dial, zone, results)

	sz = &signedZone{
		zone: zone,
	}
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err != nil {
			if err == nil { // first error encountered
				err = result.err
				cancel()
			}
			continue
		}
		if result.t == dns.TypeDS {
			sz.dsRRSig, sz.dsRRSet = result.rrsig, result.rrset
		} else {
			sz.dnsKeyRRSig, sz.dnsKeyRRSet = result.rrsig, result.rrset
			sz.keyTagToDNSKey = dnsKeyRRSetToMap(result.rrset)
		}
	}
	close(results)

	if err != nil {
		return nil, err
	}

	return sz, nil
}

var (
	ErrRecordNotFound = errors.New("record not found")
	ErrRRSigNotFound  = errors.New("RRSIG not found")
)

func queryDNSKey(ctx context.Context, dial DialFunc, client *dns.Client,
	zone string) (rrsig *dns.RRSIG, rrset []dns.RR, err error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot dial DNS server: %w", err)
	}
	defer conn.Close()

	rrsig, rrset, err = fetchRRSetWithRRSig(
		client, conn, zone, dns.TypeDNSKEY)
	switch {
	case err != nil:
		return nil, nil, err
	case len(rrset) == 0:
		return nil, nil, ErrRecordNotFound
	case rrsig == nil:
		return nil, nil, ErrRRSigNotFound
	}
	return rrsig, rrset, nil
}

func queryDS(ctx context.Context, dial DialFunc, client *dns.Client,
	zone string) (rrsig *dns.RRSIG, rrset []dns.RR, err error) {
	conn, err := dial(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot dial DNS server: %w", err)
	}
	defer conn.Close()

	rrsig, rrset, err = fetchRRSetWithRRSig(
		client, conn, zone, dns.TypeDS)
	switch {
	case err != nil:
		return nil, nil, err
	case len(rrset) == 0:
		return nil, nil, ErrRecordNotFound
	case rrsig == nil:
		return nil, nil, ErrRRSigNotFound
	}
	return rrsig, rrset, nil
}

var (
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
		return ErrRRSigNotFound
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
