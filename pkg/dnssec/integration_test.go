package dnssec

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_Validate(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		zone       string
		dnsType    uint16
		settings   Settings
		errWrapped error
		errMessage string
	}{
		"valid DNSSEC": {
			zone:    "qqq.ninja.",
			dnsType: dns.TypeA,
		},
		"bad DNSSEC": {
			zone:    "github.com.",
			dnsType: dns.TypeA,
		},
		"DNS key not found": {
			zone:       "www.dnssec-failed.org.",
			dnsType:    dns.TypeA,
			errWrapped: ErrDNSKeyNotFound,
			errMessage: "cannot create delegation chain: " +
				"cannot query delegation for www.dnssec-failed.org.: " +
				"DNS Key record not found",
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

			validator := NewValidator(testCase.settings)

			err := validator.Validate(ctx, testCase.zone, testCase.dnsType)

			assert.ErrorIs(t, err, testCase.errWrapped)
			if testCase.errWrapped != nil {
				assert.EqualError(t, err, testCase.errMessage)
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
	// Benchmark_Validate-8   	      10	 121111130 ns/op	  151557 B/op	     602 allocs/op
	// Benchmark_Validate-8   	      21	  66569610 ns/op	  155365 B/op	     654 allocs/op
}
