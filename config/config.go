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
	SMTP    SmtpProbe     `yaml:"smtp,omitempty"`
}

type ImapReceiver struct {
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

type SmtpProbe struct {
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
	IMAP               ImapReceiver      `yaml:"imap,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (s *SmtpProbe) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*s = SmtpProbe{}
	type plain SmtpProbe
	if err := unmarshal((*plain)(s)); err != nil {
		return err
	}

	if len(s.MailFrom) == 0 {
		// TODO: encorce a non-emtpy from header?
		s.MailFrom = s.Headers["from"]
	}

	if len(s.MailTo) == 0 {
		// TODO: encorce a non-emtpy to header?
		s.MailTo = s.Headers["to"]
	}

	if len(s.TLS) == 0 {
		s.TLS = "no"
	}

	r, _ := regexp.Compile(`^(no|starttls|tls)$`)
	if !r.MatchString(s.TLS) {
		return fmt.Errorf("tls value must be a an empty string (implicit no) or no|starttls|tls. prober=smtp tls=%s", s.TLS)
	}

	if len(s.EHLO) == 0 {
		s.EHLO = "localhost"
	}

	return nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (i *ImapReceiver) UnmarshalYAML(unmarshal func(interface{}) error) error {

	//FailIfSPFNotMatches, FailIfDKIMNotMatches and FailIfDMARCNotMatches defaults to false
	*i = ImapReceiver{}
	type plain ImapReceiver
	if err := unmarshal((*plain)(i)); err != nil {
		return err
	}

	if len(i.Server) == 0 {
		return fmt.Errorf("IMAP server must not be empty. server='%s'", i.Server)
	}

	if i.Port == 0 {
		return fmt.Errorf("IMAP port must not be empty. port='%d'", i.Port)
	}

	if len(i.Mailbox) == 0 {
		i.Mailbox = "INBOX"
	}

	if len(i.TLS) == 0 {
		i.TLS = "no"
	}

	r, _ := regexp.Compile(`^(no|starttls|tls)$`)
	if !r.MatchString(i.TLS) {
		return fmt.Errorf("tls value must be a an empty string (implicit no) or no|starttls|tls. prober=smtp tls=%s", i.TLS)
	}

	if len(i.TLSConfig.ServerName) == 0 {
		i.TLSConfig.ServerName = i.Server
	}

	if len(i.ValidSPFResult) == 0 {
		i.ValidSPFResult = "pass"
	}

	if len(i.ValidDKIMResult) == 0 {
		i.ValidDKIMResult = "pass"
	}

	if len(i.ValidDMARCResult) == 0 {
		i.ValidDMARCResult = "pass"
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
