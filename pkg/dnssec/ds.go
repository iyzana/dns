package dnssec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var (
	ErrInvalidDS           = errors.New("DS RR record does not match DNS key")
	ErrUnknownDsDigestType = errors.New("unknown DS digest type")
)

func verifyDS(receivedDS *dns.DS, dnsKey *dns.DNSKEY) error {
	calculatedDS := dnsKey.ToDS(receivedDS.DigestType)
	if calculatedDS == nil {
		return fmt.Errorf("%w: %s", ErrUnknownDsDigestType,
			dns.HashToString[receivedDS.DigestType])
	}

	if !strings.EqualFold(receivedDS.Digest, calculatedDS.Digest) {
		return fmt.Errorf("%w: DS record has digest %s "+
			"but calculated digest is %s", ErrInvalidDS,
			receivedDS.Digest, calculatedDS.Digest)
	}

	return nil
}
