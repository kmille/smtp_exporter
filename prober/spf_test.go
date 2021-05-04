package prober

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSPFProberWithoutTimeout(t *testing.T) {

	var defaultSPFModule = config.Module{
		Prober: "spf",
	}

	var spfModulePass = config.Module{
		Prober: "spf",
		SPF: config.SPFProbe{
			ValidSPFResult: "pass",
			Domains: []string{
				"androidloves.me",
			},
		},
	}

	var spfModuleFail = config.Module{
		Prober: "spf",
		SPF: config.SPFProbe{
			ValidSPFResult: "fail",
			Domains: []string{
				"androidloves.me",
			},
		},
	}

	var spfModuleFirstDomainFails = config.Module{
		Prober: "spf",
		SPF: config.SPFProbe{
			ValidSPFResult: "pass",
			Domains: []string{
				"gmail.com",
				"androidloves.me",
			},
		},
	}

	var spfModuleSecondDomainFails = config.Module{
		Prober: "spf",
		SPF: config.SPFProbe{
			ValidSPFResult: "pass",
			Domains: []string{
				"androidloves.me",
				"gmail.com",
			},
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
			config:         defaultSPFModule,
			expectedResult: false,
			message:        "The target must be a valid ip address without a port",
		},
		{
			target:         "mail01.example.com",
			config:         defaultSPFModule,
			expectedResult: false,
			message:        "The target must be a valid ip address",
		},
		{
			target:         "127.0.0.1:8080",
			config:         defaultSPFModule,
			expectedResult: false,
			message:        "The target must be a valid ip address without a port",
		},
		{
			target:         "999.55.234.1",
			config:         defaultSPFModule,
			expectedResult: false,
			message:        "The target must be a valid ip address",
		},
		{
			target:         "138.201.174.101",
			config:         spfModulePass,
			expectedResult: true,
			message:        "domain=androidloves.me result=pass",
		},
		{
			target:         "2a01:4f8:c17:5036::2",
			config:         spfModulePass,
			expectedResult: true,
			message:        "domain=androidloves.me result=pass",
		},
		{
			// ip is allowed to send mail, but the config expects a "fail"
			target:         "138.201.174.101",
			config:         spfModuleFail,
			expectedResult: false,
			message:        "validSPFResult=fail",
		},
		{
			// ip is allowed to send mail, but the config expects a "fail"
			target:         "2a01:4f8:c17:5036::2",
			config:         spfModuleFail,
			expectedResult: false,
			message:        "validSPFResult=fail",
		},
		{
			target:         "138.201.174.111", // ip is not allowed to send mail
			config:         spfModuleFail,
			expectedResult: true,
			message:        "domain=androidloves.me result=fail",
		},
		{
			target:         "2a01:4f8:c17:5036::222", // ip is not allowed to send mail
			config:         spfModuleFail,
			expectedResult: true,
			message:        "domain=androidloves.me result=fail",
		},
		{
			target:         "138.201.174.101", // ip is allowed to send mails for androidloves.me, but not for gmail.com
			config:         spfModuleFirstDomainFails,
			expectedResult: false,
			message:        "domain=gmail.com result=softfail",
		},
		{
			target:         "2a01:4f8:c17:5036::2", // ip is allowed to send mails for androidloves.me, but not for gmail.com
			config:         spfModuleFirstDomainFails,
			expectedResult: false,
			message:        "domain=gmail.com result=softfail",
		},
		{
			target:         "138.201.174.101", // ip is allowed to send mails for androidloves.me, but not for gmail.com
			config:         spfModuleSecondDomainFails,
			expectedResult: false,
			message:        "domain=gmail.com result=softfail",
		},
		{
			target:         "2a01:4f8:c17:5036::2", // ip is allowed to send mails for androidloves.me, but not for gmail.com
			config:         spfModuleSecondDomainFails,
			expectedResult: false,
			message:        "domain=gmail.com result=softfail",
		},
	}
	for _, test := range tests {
		logCapture := &bytes.Buffer{}
		probeResult := SPFProber(context.Background(), test.target, test.config, prometheus.NewRegistry(), log.NewLogfmtLogger(logCapture))
		if probeResult.Success != test.expectedResult || !strings.Contains(logCapture.String(), test.message) {
			t.Fatalf("SPFProber does not work target=%q, result=%t, expectedResult=%t, expectedLog=%q, actualLog=\n%s",
				test.target, probeResult.Success, test.expectedResult, test.message, logCapture)
		}
	}
}

func TestSPFProberWithTimeout(t *testing.T) {

	var spfModulePass = config.Module{
		Prober: "spf",
		SPF: config.SPFProbe{
			ValidSPFResult: "pass",
			Domains: []string{
				"androidloves.me",
			},
		},
	}

	target := "138.201.174.101"
	expectedResult := false
	message := `Execution timeout" err="context canceled`

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	// simulate timeout
	cancel()

	logCapture := &bytes.Buffer{}
	probeResult := SPFProber(ctx, target, spfModulePass, prometheus.NewRegistry(), log.NewLogfmtLogger(logCapture))
	if probeResult.Success != expectedResult || !strings.Contains(logCapture.String(), message) {
		t.Fatalf("SPFProber does not work target=%q, result=%t, expectedResult=%t, expectedLog=%q, actualLog=\n%s",
			target, probeResult.Success, expectedResult, message, logCapture)
	}
}
