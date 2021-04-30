package prober

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func DNSBLProber(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) ProbeResult {

	var blacklisted bool

	result := ProbeResult{
		Commands: &bytes.Buffer{},
		Success:  false}

	_, _, err := net.SplitHostPort(target)
	if err == nil {
		level.Error(logger).Log("msg", "Error validating target parameter. The target must be an ip address without a port (ipv4 or ipv6)")
		return result
	}

	ip := net.ParseIP(target)
	if ip == nil {
		level.Error(logger).Log("msg", "Error parsing target parameter. The target must be an ip address")
	}

	resolver := net.DefaultResolver
	// for testing
	// https://www.spamhaus.org/faq/section/DNSBL%20Usage#366
	// resolver.PreferGo = true
	// resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
	// 	d := net.Dialer{
	// 		Timeout: time.Millisecond * time.Duration(10000),
	// 	}
	// 	return d.DialContext(ctx, network, "1.1.1.6:53")
	// }

	//len(config.DefaultDNSBLProbe.Blacklists)
	const numBlacklists = 4
	const paralellJobs = 5
	jobs := make(chan string, numBlacklists)
	results := make(chan bool, numBlacklists)

	// start worker
	for i := 0; i < paralellJobs; i++ {
		go checkBlacklistWorker(ctx, logger, jobs, results, ip, resolver)
	}

	for i := 0; i < numBlacklists; i++ {
		fmt.Println(config.DNSBLProbe.Blacklists[i])
		// jobs <- config.DNSBLProbe.Blacklists[i]
	}
	close(jobs)

	for i := 0; i < numBlacklists; i++ {
		result := <-results
		if result {
			blacklisted = true
		}

	}

	if !blacklisted {
		level.Info(logger).Log("msg", "Target is not on a blacklist")
		result.Success = true
	}

	return result
}

func checkBlacklistWorker(ctx context.Context, logger log.Logger, jobs <-chan string, results chan<- bool, ip net.IP, resolver *net.Resolver) {
	var reason string

	for blacklist := range jobs {

		// dnsbl format: target 62.180.228.192 => 192.228.180.62.blacklist.com
		host := fmt.Sprintf("%s.%s", reverseIP(ip), blacklist)

		_, err := resolver.LookupHost(ctx, host)
		// // handle dns timeout
		// if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		// 	level.Error(logger).Log("msg", "Error resolving host", "err", networkErr)
		// 	return result
		// }
		// we are not on the blacklist - dns: "no such host"
		if err != nil {
			results <- false
			return
		}

		txt, err := resolver.LookupTXT(ctx, host)

		// // handle dns timeout
		// if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
		// 	level.Error(logger).Log("msg", "Error resolving blacklist reason (txt)", "err", networkErr)
		// 	return result
		// }

		if err == nil {
			reason = txt[0]
		} else {
			// no reason found (not mandatory) - dns: "no such host"
			reason = "unknown"
		}
		level.Error(logger).Log("msg", "Target found on a blacklist", "blacklist", blacklist, "reason", reason)
		results <- true
	}
}

func reverseIP(ip net.IP) string {

	if ip.To4() != nil {
		ipParts := strings.Split(ip.String(), ".")
		return fmt.Sprintf("%s.%s.%s.%s", ipParts[3], ipParts[2], ipParts[1], ipParts[0])
	}

	// credit: https://stackoverflow.com/questions/52002205/is-there-an-inbuilt-function-to-expand-ipv6-addresses
	ipHexEncoded := make([]byte, hex.EncodedLen(len(ip)))

	// get fe800001000000000000000000000af0 ([]byte]) out of fe80:1::af0 ([]byte)
	_ = hex.Encode(ipHexEncoded, ip)

	return string(ipHexEncoded[0:4]) + ":" +
		string(ipHexEncoded[4:8]) + ":" +
		string(ipHexEncoded[8:12]) + ":" +
		string(ipHexEncoded[12:16]) + ":" +
		string(ipHexEncoded[16:20]) + ":" +
		string(ipHexEncoded[20:24]) + ":" +
		string(ipHexEncoded[24:28]) + ":" +
		string(ipHexEncoded[28:])
}
