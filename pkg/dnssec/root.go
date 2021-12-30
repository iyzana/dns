package dnssec

import (
	"github.com/miekg/dns"
)

const (
	rootAnchorKeyTag = 20326
	rootAnchorDigest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
)

func verifyRootSignedZone(sz *signedZone) (err error) {
	rootAnchor := &dns.DS{
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		KeyTag:     rootAnchorKeyTag,
		Digest:     rootAnchorDigest,
	}

	return sz.verifyDS(rootAnchor)
}
