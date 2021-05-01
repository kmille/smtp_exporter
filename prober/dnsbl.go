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

// module.DNSBL.Blacklists = []string{
// 	"zen.spamhaus.org",
// 	"b.barracudacentral.org",
// 	"bl.spamcop.net",
// 	"dnsbl.sorbs.net",
// 	"five-ten-sg.com",
// 	"db.wpbl.info",
// 	"ix.dnsbl.manitu.net",
// }

var defaultBlacklists = []string{
	"aspews.ext.sorbs.net",
	"b.barracudacentral.org",
	"bl.deadbeef.com",
	"bl.emailbasura.org",
	"bl.spamcannibal.org",
	"bl.spamcop.net",
	"blackholes.five-ten-sg.com",
	"blacklist.woody.ch",
	"bogons.cymru.com",
	"cbl.abuseat.org",
	"cdl.anti-spam.org.cn",
	"combined.abuse.ch",
	"combined.rbl.msrbl.net",
	"db.wpbl.info",
	"dnsbl-1.uceprotect.net",
	"dnsbl-2.uceprotect.net",
	"dnsbl-3.uceprotect.net",
	"dnsbl.cyberlogic.net",
	"dnsbl.dronebl.org",
	"dnsbl.inps.de",
	"dnsbl.njabl.org",
	"dnsbl.sorbs.net",
	"drone.abuse.ch",
	"duinv.aupads.org",
	"dul.dnsbl.sorbs.net",
	"dul.ru",
	"dyna.spamrats.com",
	"dynip.rothen.com",
	"http.dnsbl.sorbs.net",
	"images.rbl.msrbl.net",
	"ips.backscatterer.org",
	"ix.dnsbl.manitu.net",
	"korea.services.net",
	"misc.dnsbl.sorbs.net",
	"noptr.spamrats.com",
	"ohps.dnsbl.net.au",
	"omrs.dnsbl.net.au",
	"orvedb.aupads.org",
	"osps.dnsbl.net.au",
	"osrs.dnsbl.net.au",
	"owfs.dnsbl.net.au",
	"owps.dnsbl.net.au",
	"pbl.spamhaus.org",
	"phishing.rbl.msrbl.net",
	"probes.dnsbl.net.au",
	"proxy.bl.gweep.ca",
	"proxy.block.transip.nl",
	"psbl.surriel.com",
	"rdts.dnsbl.net.au",
	"relays.bl.gweep.ca",
	"relays.bl.kundenserver.de",
	"relays.nether.net",
	"residential.block.transip.nl",
	"ricn.dnsbl.net.au",
	"rmst.dnsbl.net.au",
	"sbl.spamhaus.org",
	"short.rbl.jp",
	"smtp.dnsbl.sorbs.net",
	"socks.dnsbl.sorbs.net",
	"spam.abuse.ch",
	"spam.dnsbl.sorbs.net",
	"spam.rbl.msrbl.net",
	"spam.spamrats.com",
	"spamlist.or.kr",
	"spamrbl.imp.ch",
	"t3direct.dnsbl.net.au",
	"tor.dnsbl.sectoor.de",
	"torserver.tor.dnsbl.sectoor.de",
	"ubl.lashback.com",
	"ubl.unsubscore.com",
	"virbl.bit.nl",
	"virus.rbl.jp",
	"virus.rbl.msrbl.net",
	"web.dnsbl.sorbs.net",
	"wormrbl.imp.ch",
	"xbl.spamhaus.org",
	"zen.spamhaus.org",
	"zombie.dnsbl.sorbs.net",
}

// DNSBL is specified in https://tools.ietf.org/html/rfc5782
func DNSBLProber(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) ProbeResult {

	var blacklisted bool
	var blacklists []string

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
	// 	// return d.DialContext(ctx, network, "1.1.1.6:53")
	// 	return d.DialContext(ctx, network, "192.168.10.1:53")
	// }

	// TODO: try to resolve every host at startup?

	if len(module.DNSBL.Blacklists) == 0 {
		blacklists = defaultBlacklists
	} else {
		blacklists = module.DNSBL.Blacklists
	}

	numBlacklists := len(blacklists)
	const paralellJobs = 5
	jobs := make(chan string, numBlacklists)
	results := make(chan bool, numBlacklists)

	// start worker
	for i := 0; i < paralellJobs; i++ {
		go checkBlacklistWorker(ctx, logger, jobs, results, ip, resolver)
	}

	// give work to the worker
	for i := 0; i < numBlacklists; i++ {
		jobs <- blacklists[i]
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

func checkBlacklistWorker(ctx context.Context, logger log.Logger, jobs <-chan string, results chan<- bool, ip net.IP, resolver *net.Resolver) {
	var reason string

	for {

		select {
		case <-ctx.Done():
			// BUG? we are writing more than len(blacklists) into the results channel?
			results <- true
		case blacklist, isOpen := <-jobs:

			if !isOpen {
				return
			}

			host := fmt.Sprintf("%s.%s", rDNSFormat(ip), blacklist)
			_, err := resolver.LookupHost(ctx, host)
			// handle dns timeout
			if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
				level.Error(logger).Log("msg", "Error resolving host", "blacklist", blacklist, "err", networkErr)
				results <- true
				break
			}
			// we are not on the blacklist - dns: "no such host"
			if err != nil {
				results <- false
				break
			}

			txt, err := resolver.LookupTXT(ctx, host)
			// handle dns timeout
			if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
				level.Error(logger).Log("msg", "Error resolving blacklist reason (txt)", "blacklist", blacklist, "err", networkErr)
				results <- true
				break
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
