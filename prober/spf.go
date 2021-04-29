package prober

import (
	"bytes"
	"context"
	"net"

	"blitiri.com.ar/go/spf"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

type spfResult struct {
	result spf.Result
	reason error
}

// CheckHost currently does not support context (but it is in the next release)
func doSPFCheck(c chan spfResult, ip net.IP, domain string) {
	result, reason := spf.CheckHost(ip, domain)
	c <- spfResult{result: result,
		reason: reason}
}

func SPFProber(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) ProbeResult {

	result := ProbeResult{
		Commands: &bytes.Buffer{},
		Success:  false}

	// // should work
	// ip := net.ParseIP("138.201.174.101")
	// r, err := spf.CheckHost(ip, "androidloves.me")
	// fmt.Println("result", r, "err", err)

	// // should not work
	// ip = net.ParseIP("62.180.228.1")
	// r, err = spf.CheckHost(ip, "androidloves.me")
	// fmt.Println("result", r, "err", err)

	_, _, err := net.SplitHostPort(target)
	if err == nil {
		level.Error(logger).Log("msg", "Error validating target parameter. The target must be an ip address without a port (ipv4 or ipv6)")
		return result
	}

	ip := net.ParseIP(target)
	if ip == nil {
		level.Error(logger).Log("msg", "Error parsing target parameter. The target must be an ip address")
	}

	result.Success = true
	c := make(chan spfResult)

	for _, domain := range module.SPF.Domains {

		go doSPFCheck(c, ip, domain)
		select {
		case res := <-c:
			if res.result != spf.Result(module.SPF.ValidSPFResult) {
				level.Info(logger).Log("msg", "SPF result does not match", "domain", domain, "result", res.result, "reason", res.reason, "validSPFResult", module.SPF.ValidSPFResult)
				result.Success = false
				return result
			} else {
				level.Debug(logger).Log("msg", "SPF result matches", "domain", domain, "result", res.result, "reason", res.reason, "validSPFResult", module.SPF.ValidSPFResult)
			}
		case <-ctx.Done():
			level.Error(logger).Log("msg", "Error checking SPF", "err", ctx.Err())
			result.Success = false
			return result
		}

	}
	return result

}
