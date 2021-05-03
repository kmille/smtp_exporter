package prober

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

// DNSBL is specified in https://tools.ietf.org/html/rfc5782
func DNSBLProber(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) ProbeResult {

	var blacklisted bool

	result := ProbeResult{Success: false}

	_, _, err := net.SplitHostPort(target)
	if err == nil {
		level.Error(logger).Log("msg", "Error validating target parameter. The target must be an ip address without a port (ipv4 or ipv6)")
		return result
	}

	ip := net.ParseIP(target)
	if ip == nil {
		level.Error(logger).Log("msg", "Error parsing target parameter. The target must be a valid ip address")
		return result
	}

	numBlacklists := len(module.DNSBL.Blacklists)
	const paralellJobs = 5
	jobs := make(chan string, numBlacklists)
	results := make(chan bool, numBlacklists)

	// start worker
	for i := 0; i < paralellJobs; i++ {
		go checkBlacklist(ctx, logger, jobs, results, ip, module.DNSBL.FailOnBlacklistTimeout)
	}

	// give work to the worker
	for i := 0; i < numBlacklists; i++ {
		jobs <- module.DNSBL.Blacklists[i]
	}
	// stop all worker if they are done processing all blacklists
	close(jobs)

	for i := 0; i < numBlacklists; i++ {
		hit := <-results
		if hit {
			blacklisted = true
		}
	}

	if !blacklisted {
		level.Info(logger).Log("msg", "Target is not on a blacklist")
		result.Success = true
	}

	return result
}

func checkBlacklist(ctx context.Context, logger log.Logger, jobs <-chan string, results chan<- bool, ip net.IP, timeoutResult bool) {
	var reason string
	resolver := &net.Resolver{}
	// for testing
	// https://www.spamhaus.org/faq/section/DNSBL%20Usage#366
	// resolver.PreferGo = true
	// resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
	// 	d := net.Dialer{
	// 		Timeout: time.Millisecond * time.Duration(10000),
	// 	}
	// 	return d.DialContext(ctx, network, "1.1.1.6:53")
	// 	//return d.DialContext(ctx, network, "192.168.10.1:53")
	// }

	for {

		blacklist, isOpen := <-jobs
		if !isOpen {
			return
		}

		if errors.Is(ctx.Err(), context.Canceled) {
			level.Error(logger).Log("msg", "Execution timeout", "blacklist", blacklist, "err", ctx.Err())
			results <- timeoutResult
			continue
		}

		host := fmt.Sprintf("%s.%s", rDNSFormat(ip), blacklist)
		_, err := resolver.LookupHost(ctx, host)

		// handle dns timeout
		if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
			level.Error(logger).Log("msg", "Error resolving host", "blacklist", blacklist, "err", networkErr)
			results <- timeoutResult
			continue
		}

		// not on the blacklist - dns: "no such host"
		if err != nil {
			results <- false
			continue
		}

		txt, err := resolver.LookupTXT(ctx, host)
		// handle dns timeout
		if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
			level.Error(logger).Log("msg", "Error resolving TXT record (blacklist reason)", "blacklist", blacklist, "err", networkErr)
			results <- timeoutResult
			continue
		}
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

// rDNSFormat formats ip addresses in to required RDNSBL format
// 62.180.228.192 becomes 192.228.180.62
// 2606:4700:4700::1111 becomes 1.1.1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.7.4.0.0.7.4.6.0.6
func rDNSFormat(ip net.IP) string {
	var ip6Reversed bytes.Buffer

	// credit: inspired by https://github.com/kiwiirc/webircgateway/blob/f66bb6235964ba0291d7982cbad360400a4e566d/pkg/dnsbl/dnsbl.go
	if ip.To4() != nil {
		ipParts := strings.Split(ip.String(), ".")
		return fmt.Sprintf("%s.%s.%s.%s", ipParts[3], ipParts[2], ipParts[1], ipParts[0])
	}

	ip6Expanded := expandIPv6(ip)
	ip6Expanded = strings.ReplaceAll(ip6Expanded, ":", "")
	for i := len(ip6Expanded) - 1; i > 0; i-- {
		ip6Reversed.WriteByte(ip6Expanded[i])
	}
	return strings.Join(strings.Split(ip6Reversed.String(), ""), ".")
}

// exapend ip6 address
// 2606:4700:4700::1111 becomes 2606:4700:4700:0000:0000:0000:0000:1111
func expandIPv6(ip net.IP) string {
	ipHexEncoded := make([]byte, hex.EncodedLen(len(ip)))
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
