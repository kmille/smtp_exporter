package prober

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"time"

	"github.com/go-kit/kit/log"

	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

var protocolToGauge = map[string]float64{
	"ip4": 4,
	"ip6": 6,
}

func chooseProtocol(ctx context.Context, IPProtocol string, fallbackIPProtocol bool, target string, registry *prometheus.Registry, logger log.Logger) (ip *net.IPAddr, lookupTime float64, returnerr error) {
	var fallbackProtocol string
	probeDNSLookupTimeSeconds := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_lookup_time_seconds",
		Help: "Returns the time taken for probe dns lookup in seconds",
	})

	probeIPProtocolGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies wether probe ip protocol IP4 or IP6",
	})

	probeIPAddrHash := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_addr_hash",
		Help: "Specifies the hash of IP address. It's useful to detect if the IP address changes.",
	})

	registry.MustRegister(probeIPProtocolGauge)
	registry.MustRegister(probeDNSLookupTimeSeconds)
	registry.MustRegister(probeIPAddrHash)

	if IPProtocol == "ip6" || IPProtocol == "" {
		IPProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		IPProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	var usedProtocol string

	resolveStart := time.Now()

	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
		probeDNSLookupTimeSeconds.Add(lookupTime)
		if usedProtocol != "" {
			probeIPProtocolGauge.Set(protocolToGauge[usedProtocol])
		}
		if ip != nil {
			probeIPAddrHash.Set(ipHash(ip.IP))
		}
	}()

	resolver := &net.Resolver{}

	level.Info(logger).Log("msg", "Resolving target addreses", "targetHost", target, "ip_protocol", IPProtocol)
	if ips, err := resolver.LookupIP(ctx, IPProtocol, target); err == nil {
		level.Info(logger).Log("msg", "Resolved target address", "ip", ips[0].String())
		usedProtocol = IPProtocol
		ip = &net.IPAddr{IP: ips[0]}
		return
	} else if !fallbackIPProtocol {
		level.Error(logger).Log("msg", "Resolution with IP protocol failed", "err", err)
		returnerr = fmt.Errorf("unable to find ip; no fallback: %s", err)
		return
	}

	level.Info(logger).Log("msg", "Resolving target address", "ip_protocol", fallbackProtocol)
	ips, err := resolver.LookupIP(ctx, fallbackProtocol, target)
	if err != nil {
		level.Error(logger).Log("msg", "Resolution with IP protocol failed", "err", err)
		returnerr = fmt.Errorf("unable to find ip; exhausted fallback: %s", err)
		return
	}
	level.Info(logger).Log("msg", "Resolved target address", "ip", ips[0].String())
	usedProtocol = fallbackProtocol
	ip = &net.IPAddr{IP: ips[0]}
	return
}

func ipHash(ip net.IP) float64 {
	h := fnv.New32a()
	h.Write(ip)
	return float64(h.Sum32())
}
