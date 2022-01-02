package dnssec

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_validator_fetchAndValidateZone(t *testing.T) {
	t.Parallel()

	const validZone = "qqq.ninja."
	request := new(dns.Msg).SetQuestion(validZone, dns.TypeA)
	response, _, err := new(dns.Client).Exchange(request, "1.1.1.1:53")
	require.NoError(t, err)
	validZoneRRSet := response.Answer
	for i := range validZoneRRSet {
		validZoneRRSet[i].Header().Ttl = 0
	}

	testCases := map[string]struct {
		zone        string
		dnsType     uint16
		settings    Settings
		rrset       []dns.RR
		errWrapped  error
		errMsgRegex string
	}{
		"valid DNSSEC": {
			zone:    "qqq.ninja.",
			dnsType: dns.TypeA,
			rrset:   validZoneRRSet,
		},
		"no DNSSEC": {
			zone:       "github.com.",
			dnsType:    dns.TypeA,
			errWrapped: ErrRecordNotFound,
			errMsgRegex: "cannot create delegation chain: " +
				"cannot query delegation for github\\.com\\.: " +
				"cannot fetch (DNSKEY|DS) records: " +
				"record not found",
		},
		"bad DNSSEC": {
			zone:       "www.dnssec-failed.org.",
			dnsType:    dns.TypeA,
			errWrapped: ErrRecordNotFound,
			errMsgRegex: "cannot create delegation chain: " +
				"cannot query delegation for (www\\.|)dnssec-failed\\.org\\.: " +
				"cannot fetch (DNSKEY|DS) records: " +
				"record not found",
		},
	}
	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			errMsgRegex, err := regexp.Compile(testCase.errMsgRegex)
			require.NoError(t, err)

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
			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.Regexp(t, errMsgRegex, err.Error())
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
