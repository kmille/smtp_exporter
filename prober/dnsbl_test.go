package prober

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"

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

	var defaultDNSBLConfig = config.Module{
		Prober: "dnsbl",
	}

	tests := []struct {
		target         string
		config         config.Module
		expectedResult bool
		message        string
	}{
		{
			target:         "mail01.example.com:8080",
			config:         defaultDNSBLConfig,
			expectedResult: false,
			message:        "The target must be an ip address without a port",
		},
		{
			target:         "mail01.example.com",
			config:         defaultDNSBLConfig,
			expectedResult: false,
			message:        "The target must be a valid ip address",
		},
		{
			target:         "127.0.0.1:8080",
			config:         defaultDNSBLConfig,
			expectedResult: false,
			message:        "Error validating target parameter. The target must be an ip address without a port",
		},
		{
			target:         "542.5654.234.234234234",
			config:         defaultDNSBLConfig,
			expectedResult: false,
			message:        "The target must be a valid ip address",
		},
		{
			// IPv4-based DNSxLs MUST contain an entry for 127.0.0.2 for testing purposes https://tools.ietf.org/html/rfc5782#section-5
			target:         "127.0.0.2",
			config:         defaultDNSBLConfig,
			expectedResult: false,
			message:        "Target found on a blacklist",
		},
		// {
		// 	target:         "127.0.0.2",
		// 	config:         defaultDNSBLConfig,
		// 	expectedResult: true,
		// },
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

/*
Tests

syntax error (no ip, hostname)
default blacklist
custom blacklist
success
false
mixed list
timeout
ipv6

*/
