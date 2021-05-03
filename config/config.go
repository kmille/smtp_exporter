package config

import (
	"fmt"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/config"

	yaml "gopkg.in/yaml.v3"
)

var (
	configReloadSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "smtp_exporter",
		Name:      "config_last_reload_successful",
		Help:      "smtp exporter config loaded successfully.",
	})

	configReloadSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "smtp_exporter",
		Name:      "config_last_reload_success_timestamp_seconds",
		Help:      "Timestamp of the last successful configuration reload.",
	})

	DefaultModule = Module{
		SMTP:  DefaultSMTPProbe,
		DNSBL: DefaultDNSBLProbe,
		SPF:   DefaultSPFProbe,
	}

	DefaultSMTPProbe = SMTPProbe{
		IPProtocol:         "ip6",
		IPProtocolFallback: true,
		EHLO:               "localhost",
		TLS:                "no",
	}

	DefaultIMAPReceiver = IMAPReceiver{
		TLS:                   "no",
		Mailbox:               "INBOX",
		ValidSPFResult:        "pass",
		ValidDKIMResult:       "pass",
		ValidDMARCResult:      "pass",
		FailIfSPFNotMatches:   false,
		FailIfDKIMNotMatches:  false,
		FailIfDMARCNotMatches: false,
	}

	DefaultDNSBLProbe = DNSBLProbe{
		FailOnBlacklistTimeout: true,
		Blacklists: []string{
			"zen.spamhaus.org",
			"b.barracudacentral.org",
			"ix.dnsbl.manitu.net",
		},
	}

	DefaultSPFProbe = SPFProbe{
		ValidSPFResult: "pass",
	}

// Blacklists: []string{
// 	"aspews.ext.sorbs.net",
// 	"b.barracudacentral.org",
// 	"bl.deadbeef.com",
// 	"bl.emailbasura.org",
// 	"bl.spamcannibal.org",
// 	"bl.spamcop.net",
// 	"blackholes.five-ten-sg.com",
// 	"blacklist.woody.ch",
// 	"bogons.cymru.com",
// 	"cbl.abuseat.org",
// 	"cdl.anti-spam.org.cn",
// 	"combined.abuse.ch",
// 	"combined.rbl.msrbl.net",
// 	"db.wpbl.info",
// 	"dnsbl-1.uceprotect.net",
// 	"dnsbl-2.uceprotect.net",
// 	"dnsbl-3.uceprotect.net",
// 	"dnsbl.cyberlogic.net",
// 	"dnsbl.dronebl.org",
// 	"dnsbl.inps.de",
// 	"dnsbl.njabl.org",
// 	"dnsbl.sorbs.net",
// 	"drone.abuse.ch",
// 	"duinv.aupads.org",
// 	"dul.dnsbl.sorbs.net",
// 	"dul.ru",
// 	"dyna.spamrats.com",
// 	"dynip.rothen.com",
// 	"http.dnsbl.sorbs.net",
// 	"images.rbl.msrbl.net",
// 	"ips.backscatterer.org",
// 	"ix.dnsbl.manitu.net",
// 	"korea.services.net",
// 	"misc.dnsbl.sorbs.net",
// 	"noptr.spamrats.com",
// 	"ohps.dnsbl.net.au",
// 	"omrs.dnsbl.net.au",
// 	"orvedb.aupads.org",
// 	"osps.dnsbl.net.au",
// 	"osrs.dnsbl.net.au",
// 	"owfs.dnsbl.net.au",
// 	"owps.dnsbl.net.au",
// 	"pbl.spamhaus.org",
// 	"phishing.rbl.msrbl.net",
// 	"probes.dnsbl.net.au",
// 	"proxy.bl.gweep.ca",
// 	"proxy.block.transip.nl",
// 	"psbl.surriel.com",
// 	"rdts.dnsbl.net.au",
// 	"relays.bl.gweep.ca",
// 	"relays.bl.kundenserver.de",
// 	"relays.nether.net",
// 	"residential.block.transip.nl",
// 	"ricn.dnsbl.net.au",
// 	"rmst.dnsbl.net.au",
// 	"sbl.spamhaus.org",
// 	"short.rbl.jp",
// 	"smtp.dnsbl.sorbs.net",
// 	"socks.dnsbl.sorbs.net",
// 	"spam.abuse.ch",
// 	"spam.dnsbl.sorbs.net",
// 	"spam.rbl.msrbl.net",
// 	"spam.spamrats.com",
// 	"spamlist.or.kr",
// 	"spamrbl.imp.ch",
// 	"t3direct.dnsbl.net.au",
// 	"tor.dnsbl.sectoor.de",
// 	"torserver.tor.dnsbl.sectoor.de",
// 	"ubl.lashback.com",
// 	"ubl.unsubscore.com",
// 	"virbl.bit.nl",
// 	"virus.rbl.jp",
// 	"virus.rbl.msrbl.net",
// 	"web.dnsbl.sorbs.net",
// 	"wormrbl.imp.ch",
// 	"xbl.spamhaus.org",
// 	"zen.spamhaus.org",
// 	"zombie.dnsbl.sorbs.net",
// }
)

func init() {
	prometheus.MustRegister(configReloadSuccess)
	prometheus.MustRegister(configReloadSeconds)
}

type Config struct {
	Modules map[string]Module `yaml:"modules"`
}
type SafeConfig struct {
	sync.RWMutex
	C *Config
}

type SMTPAuth struct {
	Username string        `yaml:"username,omitempty"`
	Password config.Secret `yaml:"password,omitempty"`
}

type Module struct {
	Prober  string        `yaml:"prober"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	SMTP    SMTPProbe     `yaml:"smtp,omitempty"`
	SPF     SPFProbe      `yaml:"spf,omitempty"`
	DNSBL   DNSBLProbe    `yaml:"dnsbl,omitempty"`
}

type IMAPReceiver struct {
	TLS                   string           `yaml:"tls,omitempty"`
	TLSConfig             config.TLSConfig `yaml:"tls_config,omitempty"`
	Auth                  SMTPAuth         `yaml:"auth,omitempty"`
	Server                string           `yaml:"server,omitempty"`
	Port                  int              `yaml:"port,omitempty"`
	Mailbox               string           `yaml:"mailbox,omitempty"`
	ValidSPFResult        string           `yaml:"valid_spf_result,omitempty"`
	ValidDKIMResult       string           `yaml:"valid_dkim_result,omitempty"`
	ValidDMARCResult      string           `yaml:"valid_dmarc_result,omitempty"`
	FailIfSPFNotMatches   bool             `yaml:"fail_if_spf_not_matches,omitempty"`
	FailIfDKIMNotMatches  bool             `yaml:"fail_if_dkim_not_matches,omitempty"`
	FailIfDMARCNotMatches bool             `yaml:"fail_if_dmarc_not_matches,omitempty"`
}

type SMTPProbe struct {
	IPProtocol         string            `yaml:"preferred_ip_protocol,omitempty"`
	IPProtocolFallback bool              `yaml:"ip_protocol_fallback,omitempty"`
	TLS                string            `yaml:"tls,omitempty"`
	TLSConfig          config.TLSConfig  `yaml:"tls_config,omitempty"`
	Auth               SMTPAuth          `yaml:"auth,omitempty"`
	EHLO               string            `yaml:"ehlo,omitempty"`
	MailFrom           string            `yaml:"mail_from,omitempty"`
	MailTo             string            `yaml:"mail_to,omitempty"`
	Headers            map[string]string `yaml:"headers,omitempty"`
	Body               string            `yaml:"body,omitempty"`
	ValidStatusCodes   []int             `yaml:"valid_status_codes,omitempty"`
	Receiver           string            `yaml:"receiver,omitempty"`
	IMAP               IMAPReceiver      `yaml:"imap,omitempty"`
}

type SPFProbe struct {
	Domains        []string `yaml:"domains,omitempty"`
	ValidSPFResult string   `yaml:"valid_spf_result,omitempty"`
}

type DNSBLProbe struct {
	Blacklists             []string `yaml:"blacklists,omitempty"`
	FailOnBlacklistTimeout bool     `yaml:"fail_on_blacklist_timeout,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (i *IMAPReceiver) UnmarshalYAML(unmarshal func(interface{}) error) error {

	*i = DefaultIMAPReceiver
	type plain IMAPReceiver
	if err := unmarshal((*plain)(i)); err != nil {
		return err
	}

	if len(i.Server) == 0 {
		return fmt.Errorf("IMAP server must not be empty. server='%s'", i.Server)
	}

	if i.Port == 0 {
		return fmt.Errorf("IMAP port must not be empty. port='%d'", i.Port)
	}

	r, _ := regexp.Compile(`^(no|starttls|tls)$`)
	if !r.MatchString(i.TLS) {
		return fmt.Errorf("tls value must be a an empty string (implicit no) or no|starttls|tls. prober=smtp tls=%s", i.TLS)
	}

	if len(i.TLSConfig.ServerName) == 0 {
		i.TLSConfig.ServerName = i.Server
	}

	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *SMTPProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultSMTPProbe
	type plain SMTPProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	r, _ := regexp.Compile(`^(ip4|ip6)$`)
	if !r.MatchString(s.IPProtocol) {
		return fmt.Errorf("preferred_ip_protocol value must be ip4 or ip6. prober=smtp preferred_ip_protocol=%s", s.IPProtocol)
	}

	if len(s.MailFrom) == 0 {
		s.MailFrom = s.Headers["from"]
	}

	if len(s.MailTo) == 0 {
		s.MailTo = s.Headers["to"]
	}

	r, _ = regexp.Compile(`^(no|starttls|tls)$`)
	if !r.MatchString(s.TLS) {
		return fmt.Errorf("tls value must be a an empty string (implicit no) or no|starttls|tls. prober=smtp tls=%s", s.TLS)
	}

	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (d *DNSBLProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {

	*d = DefaultDNSBLProbe
	type plain DNSBLProbe
	if err := unmarshal((*plain)(d)); err != nil {
		return err
	}

	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *Module) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = DefaultModule
	type plain Module
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *SPFProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {

	*s = SPFProbe{}
	type plain SPFProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	return nil
}

func (sc *SafeConfig) ReloadConfig(confFile string) (err error) {
	var c = &Config{}
	defer func() {
		if err != nil {
			configReloadSeconds.Set(0)
		} else {
			configReloadSeconds.Set(1)
			configReloadSeconds.SetToCurrentTime()
		}
	}()
	yamlReader, err := os.Open(confFile)
	if err != nil {
		return fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	if err = decoder.Decode(c); err != nil {
		return err
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()
	return nil
}
