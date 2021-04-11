package config

import (
	"fmt"
	"os"
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
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type Module struct {
	Prober  string        `yaml:"prober"`
	Timeout time.Duration `yaml:"timeout,omitempty"`
	SMTP    SmtpProbe     `yaml:"smtp,omitempty"`
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
		return fmt.Errorf("error parsing config file: %s", err)
	}

	sc.Lock()
	sc.C = c
	sc.Unlock()
	// fmt.Printf("%v", c)

	return nil
}
