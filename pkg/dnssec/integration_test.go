package dnssec

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getRRSetWithoutValidation(t *testing.T, zone string,
	qType, qClass uint16) (rrset []dns.RR) {
	t.Helper()

	request := new(dns.Msg)
	request.SetQuestion(zone, qType)
	request.Question[0].Qclass = qClass

	response, _, err := new(dns.Client).Exchange(request, "1.1.1.1:53")
	require.NoError(t, err)

	// Clear TTL since they are not predicatable
	for _, rr := range response.Answer {
		rr.Header().Ttl = 0
	}

	return response.Answer
}

func Test_validator_fetchAndValidateZone(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		zone       string
		dnsType    uint16
		settings   Settings
		rrset      []dns.RR
		errWrapped error
		errMessage string
	}{
		"valid DNSSEC": {
			zone:    "qqq.ninja.",
			dnsType: dns.TypeA,
			rrset:   getRRSetWithoutValidation(t, "qqq.ninja.", dns.TypeA, dns.ClassINET),
		},
		"no DNSSEC": {
			zone:    "github.com.",
			dnsType: dns.TypeA,
			rrset:   getRRSetWithoutValidation(t, "github.com.", dns.TypeA, dns.ClassINET),
		},
		"bad DNSSEC already failed by upstream": {
			zone:       "dnssec-failed.org.",
			dnsType:    dns.TypeA,
			errWrapped: ErrValidationFailedUpstream,
			errMessage: "cannot fetch desired RRSet and RRSig: " +
				"for dnssec-failed.org. IN A: " +
				"DNSSEC validation might had failed upstream",
		},
	}
	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			deadline, ok := t.Deadline()
			if !ok {
				deadline = time.Now().Add(5 * time.Second)
			}

			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()

			validator := newValidator(testCase.settings)

			rrset, err := validator.fetchAndValidateZone(ctx, testCase.zone, dns.ClassINET, testCase.dnsType)

			// Remove TTL fields from rrset
			for i := range rrset {
				rrset[i].Header().Ttl = 0
			}

			assert.Equal(t, testCase.rrset, rrset)
			require.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
			}
		})
	}
}

func Benchmark_validator_fetchAndValidateZone(b *testing.B) {
	ctx := context.Background()
	const zone = "qqq.ninja."
	const dnsType = dns.TypeA
	validator := newValidator(Settings{})

	for i := 0; i < b.N; i++ {
		_, _ = validator.fetchAndValidateZone(ctx, zone, dns.ClassINET, dnsType)
	}
}
