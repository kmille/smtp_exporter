package prober

import (
	"net"
	"testing"
)

func TestReverseIP(t *testing.T) {
	input := "192.168.2.1"
	expectedResult := "1.2.168.192"
	result := rDNSFormat(net.ParseIP(input))
	if result != expectedResult {
		t.Fatalf("rDNSFormat does not work for ip4 (input=%q, result=%q, expectedResult=%q)", input, result, expectedResult)
	}

	input = "2606:4700:4700::1111"
	expectedResult = "1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6"
	result = rDNSFormat(net.ParseIP(input))
	if result != expectedResult {
		t.Fatalf("rDNSFormat does not work for ip6 (input=%q, result=%q, expectedResult=%q)", input, result, expectedResult)
	}

}

func TestExpandIPv6(t *testing.T) {
	input := "2606:4700:4700::1111"
	expectedResult := "2606:4700:4700:0000:0000:0000:0000:1111"
	result := expandIPv6(net.ParseIP(input))
	if result != expectedResult {
		t.Fatalf("expandIPv6 does not work (input=%q, result=%q, expectedResult=%q)", input, result, expectedResult)
	}
}
