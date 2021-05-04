package prober

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestReverseIP(t *testing.T) {
	target := "192.168.2.1"
	expectedResult := "1.2.168.192"
	result := rDNSFormat(net.ParseIP(target))
	if result != expectedResult {
		t.Fatalf("rDNSFormat does not work for ip4 (target=%q, result=%q, expectedResult=%q)", target, result, expectedResult)
	}

	target = "2606:4700:4700::1111"
	expectedResult = "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6"
	result = rDNSFormat(net.ParseIP(target))
	if result != expectedResult {
		t.Fatalf("rDNSFormat does not work for ip6 (target=%q, result=%q, expectedResult=%q)", target, result, expectedResult)
	}

}

func TestExpandIPv6(t *testing.T) {
	target := "2606:4700:4700::1111"
	expectedResult := "2606:4700:4700:0000:0000:0000:0000:1111"
	result := expandIPv6(net.ParseIP(target))
	if result != expectedResult {
		t.Fatalf("expandIPv6 does not work (target=%q, result=%q, expectedResult=%q)", target, result, expectedResult)
	}
}

func TestDNSBLProber(t *testing.T) {

	var defaultDNSBLModule = config.Module{
		Prober: "dnsbl",
		DNSBL:  config.DefaultDNSBLProbe,
	}

	var customDNSBLModule = config.Module{
		Prober: "dnsbl",
		DNSBL: config.DNSBLProbe{
			Blacklists: []string{
				// something like 14.110.4.42.gmail.com will never return a record (aka "not on a blacklist")
				"gmail.com",
			},
			FailOnBlacklistTimeout: true,
		},
	}

	tests := []struct {
		target         string
		config         config.Module
		expectedResult bool //probe success/fail
		message        string
	}{
		{
			target:         "mail01.example.com:8080",
			config:         defaultDNSBLModule,
			expectedResult: false,
			message:        "The target must be an ip address without a port",
		},
		{
			target:         "mail01.example.com",
			config:         defaultDNSBLModule,
			expectedResult: false,
			message:        "The target must be a valid ip address",
		},
		{
			target:         "127.0.0.1:8080",
			config:         defaultDNSBLModule,
			expectedResult: false,
			message:        "Error validating target parameter. The target must be an ip address without a port",
		},
		{
			target:         "999.55.234.1",
			config:         defaultDNSBLModule,
			expectedResult: false,
			message:        "The target must be a valid ip address",
		},
		{
			// IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes - https://tools.ietf.org/html/rfc5782#section-5
			target:         "127.0.0.2",
			config:         defaultDNSBLModule,
			expectedResult: false,
			message:        "Target found on a blacklist",
		},
		{
			// check if we iterate till the last blacklist (default blacklists)
			target:         "127.0.0.2",
			config:         defaultDNSBLModule,
			expectedResult: false,
			message:        fmt.Sprintf("%s%s", `Target found on a blacklist" blacklist=`, defaultDNSBLModule.DNSBL.Blacklists[len(defaultDNSBLModule.DNSBL.Blacklists)-1]),
		},
		{
			// IPv4-based DNSxLs MUST NOT contain an entry for 127.0.0.1 - https://tools.ietf.org/html/rfc5782#section-5
			target:         "127.0.0.1",
			config:         defaultDNSBLModule,
			expectedResult: true,
			message:        "Target is not on a blacklist",
		},
		{
			// IPv6-based DNSxLs MUST contain an entry for ::FFFF:7F00:2 - https://tools.ietf.org/html/rfc5782#section-5
			// net.ParseIP will convert "::FFFF:7F00:2" to 127.0.0.1 :/
			target:         "::FFFF:7F00:2",
			config:         defaultDNSBLModule,
			expectedResult: false,
			message:        "Target found on a blacklist",
		},
		{
			// IPv6-based DNSxLs MUST NOT contain an entry for ::FFFF:7F00:1
			target:         "::FFFF:7F00:1",
			config:         defaultDNSBLModule,
			expectedResult: true,
			message:        "Target is not on a blacklist",
		},
		{
			target:         "2001:41d0:701:1100:0:0:0:dc",
			config:         defaultDNSBLModule,
			expectedResult: true,
			message:        "Target is not on a blacklist",
		},
		{
			// let's test, if our custom blacklist is used
			// a blacklist must have a blacklist entry for 127.0.0.2
			// our google dummy blacklist domain does not
			target:         "127.0.0.2",
			config:         customDNSBLModule,
			expectedResult: true,
			message:        "Target is not on a blacklist",
		},
	}

	for _, test := range tests {
		logCapture := &bytes.Buffer{}
		probeResult := DNSBLProber(context.Background(), test.target, test.config, prometheus.NewRegistry(), log.NewLogfmtLogger(logCapture))
		if probeResult.Success != test.expectedResult || !strings.Contains(logCapture.String(), test.message) {
			t.Fatalf("DNSBLProbe does not work target=%q, result=%t, expectedResult=%t, expectedLog=%q, actualLog=\n%s",
				test.target, probeResult.Success, test.expectedResult, test.message, logCapture)

		}
	}

}

func TestCheckBlacklistSoftTimeoutFail(t *testing.T) {

	// test #1: regular test: 127.0.0.2 is on the blacklist (zen.spamhaus.org)
	// test #2: regular test: 127.0.0.2 is not on the blacklist (gmail.com) - gmail.com ist not a spamlist, but will return no record => not on the blacklist
	// simulate a timeout by calling cancel()
	// test #3: we should return immediately, as we run into a timeout. As we use failOnBlacklistTimeout=false, the probe will not fail

	failOnBlacklistTimeout := false

	tests := []struct {
		blacklist      string
		expectedResult bool // are we on the blacklist?
	}{
		{
			blacklist:      "zen.spamhaus.org",
			expectedResult: true,
		},
		{
			blacklist:      "gmail.com",
			expectedResult: false,
		},
		{
			blacklist: "zen.spamhaus.org",
		},
	}

	jobs := make(chan string, len(tests))
	results := make(chan bool, len(tests))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	jobs <- tests[0].blacklist
	jobs <- tests[1].blacklist

	logCapture := &bytes.Buffer{}
	ip := net.ParseIP("127.0.0.2")
	go checkBlacklist(ctx, log.NewLogfmtLogger(logCapture), jobs, results, ip, failOnBlacklistTimeout)

	for _, test := range tests[0:2] {
		result := <-results
		if result != test.expectedResult {
			t.Fatalf("TestCheckBlacklistSoftTimeoutFail does not work ip=%q blacklist=%q, result=%t, expectedResult=%t, expectedLog=%q, actualLog=\n%s",
				ip, test.blacklist, result, test.expectedResult, "", logCapture)
		}
	}

	// simulate timeout
	cancel()
	jobs <- tests[2].blacklist
	close(jobs)
	result := <-results
	if result != failOnBlacklistTimeout {
		// keep in mind: logCapture holds the log of all three test runs
		t.Fatalf("TestCheckBlacklistSoftTimeoutFail does not work ip=%q blacklist=%q, result=%t, expectedResult=%t, expectedLog=%q, actualLog=\n%s",
			ip, tests[2].blacklist, result, failOnBlacklistTimeout, "Execution timeout", logCapture)
	}
}

func TestCheckBlacklistHardTimeoutFail(t *testing.T) {

	// test #1: regular test: 127.0.0.2 is on the blacklist (zen.spamhaus.org)
	// test #2: regular test: 127.0.0.2 is not on the blacklist (gmail.com) - gmail.com ist not a spamlist, but will return no record => not on the blacklist
	// simulate a timeout by calling cancel()
	// test #3: we should return immediately, as we run into a timeout. As we use failOnBlacklistTimeout=true, the probe will fail

	failOnBlacklistTimeout := true

	tests := []struct {
		blacklist      string
		expectedResult bool // are we on the blacklist?
	}{
		{
			blacklist:      "zen.spamhaus.org",
			expectedResult: true,
		},
		{
			blacklist:      "gmail.com",
			expectedResult: false,
		},
		{
			blacklist: "zen.spamhaus.org",
		},
	}

	jobs := make(chan string, len(tests))
	results := make(chan bool, len(tests))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

	jobs <- tests[0].blacklist
	jobs <- tests[1].blacklist

	logCapture := &bytes.Buffer{}
	ip := net.ParseIP("127.0.0.2")
	go checkBlacklist(ctx, log.NewLogfmtLogger(logCapture), jobs, results, ip, failOnBlacklistTimeout)

	for _, test := range tests[0:2] {
		result := <-results
		if result != test.expectedResult {
			t.Fatalf("TestCheckBlacklistHardTimeoutFail does not work ip=%q blacklist=%q, result=%t, expectedResult=%t, expectedLog=%q, actualLog=\n%s",
				ip, test.blacklist, result, test.expectedResult, "", logCapture)
		}
	}

	// simulate timeout
	cancel()
	jobs <- tests[2].blacklist
	close(jobs)
	result := <-results
	if result != failOnBlacklistTimeout {
		// keep in mind: logCapture holds the log of all three test runs
		t.Fatalf("TestCheckBlacklistHardTimeoutFail does not work ip=%q blacklist=%q, result=%t, expectedResult=%t, expectedLog=%q, actualLog=\n%s",
			ip, tests[2].blacklist, result, failOnBlacklistTimeout, "Execution timeout", logCapture)
	}
}
