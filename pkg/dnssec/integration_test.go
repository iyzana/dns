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

func Test_Validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		zone        string
		dnsType     uint16
		settings    Settings
		errWrapped  error
		errMsgRegex string
	}{
		"valid DNSSEC": {
			zone:    "qqq.ninja.",
			dnsType: dns.TypeA,
		},
		"no DNSSEC": {
			zone:       "github.com.",
			dnsType:    dns.TypeA,
			errWrapped: ErrRecordNotFound,
			errMsgRegex: "cannot create delegation chain: " +
				"cannot query delegation for github\\.com\\.: " +
				"cannot fetch (DNSKEY|DS) records: record not found",
		},
		"bad DNSSEC": {
			zone:       "www.dnssec-failed.org.",
			dnsType:    dns.TypeA,
			errWrapped: ErrRecordNotFound,
			errMsgRegex: "cannot create delegation chain: " +
				"cannot query delegation for www\\.dnssec-failed\\.org\\.: " +
				"cannot fetch DNSKEY records: " +
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

			validator := NewValidator(testCase.settings)

			err = validator.Validate(ctx, testCase.zone, testCase.dnsType)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.Regexp(t, errMsgRegex, err.Error())
			}
		})
	}
}

func Benchmark_Validate(b *testing.B) {
	ctx := context.Background()
	const zone = "qqq.ninja."
	const dnsType = dns.TypeA
	validator := NewValidator(Settings{})

	for i := 0; i < b.N; i++ {
		_ = validator.Validate(ctx, zone, dnsType)
	}
}
