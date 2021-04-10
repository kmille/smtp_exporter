package prober

import (
	"context"
	"fmt"
	"os"

	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
)

func SmtpProber(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) (success bool) {
	/*
		ip, lookupTime, err := chooseProtocol(ctx, module.SMTP.IPProtocol, module.SMTP.IPProtocolFallback, target, registry, logger)
		fmt.Println(lookupTime)
		fmt.Println(ip)
		if err != nil {
			level.Error(logger).Log("msg", "Error resolving address", "err", err)
			return false
		}
	*/

	c, err := NewSmtpClient(target, module, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error creating a smtp client", "err", err)
		return false
	}
	c.DebugWriter = os.Stderr

	helo := module.SMTP.HELO
	if helo == "" {
		// TODO: remove port
		helo = target
	}
	err = c.Hello(helo)
	if err != nil {
		level.Error(logger).Log("msg", "Error sending HELO command", "err", err)
	}

	if module.SMTP.Auth.username == "" {
		auth := sasl.NewPlainClient("", module.SMTP.Auth.username, module.SMTP.Auth.password)
		if err = c.Auth(auth); err != nil {
			level.Error(logger).Log("msg", "Error sending AUTH command", "err", err)
		}
	}

	if err = c.Mail("blubb@blubb.de", nil); err != nil {
		level.Error(logger).Log("msg", "Error sending MAIL FROM command", "err", err)

	}
	if err = c.Rcpt("christian.schneider@androidloves.me"); err != nil {
		level.Error(logger).Log("msg", "Error sending MAIL TO command", "err", err)
	}
	w, err := c.Data()
	if err != nil {
		level.Error(logger).Log("msg", "Error sending DATA command", "err", err)
	}
	headers := make(map[string]string)
	headers["From"] = "christian.schneider@androidloves.me"
	headers["To"] = "test123@androidloves.me"
	headers["Subject"] = "subject"
	headers["Message-ID"] = "gib ruh"
	headers["Date"] = "Wed, 17 Mar 2021 09:26:53 +0100"
	body := "this is the body"

	// Setup message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	_, err = w.Write([]byte(message))
	if err != nil {
		level.Error(logger).Log("msg", "Could not send email ", "err", err)
	}
	err = w.Close()
	if err != nil {
		level.Error(logger).Log("msg", "Could not close email buffer", "err", err)
	}

	err = c.Quit()
	if err != nil {
		level.Error(logger).Log("msg", "Could not send QUIT", err)
	}
	return true
}

func NewSmtpClient(target string, module config.Module, logger log.Logger) (*smtp.Client, error) {
	var c *smtp.Client
	var err error
	// TODO: fallback if empty
	if module.SMTP.TLS == "no" {
		c, err = smtp.Dial(target)
		if err != nil {
			return nil, err
		}
	}

	if module.SMTP.TLS == "starttls" {
		c, err = smtp.Dial(target)
		if err != nil {
			return nil, err
		}
		TLSConfig, err := pconfig.NewTLSConfig(&module.SMTP.TLSConfig)
		if err != nil {
			return nil, err
		}
		c.StartTLS(TLSConfig)
	}

	if module.SMTP.TLS == "yes" {

		TLSConfig, err := pconfig.NewTLSConfig(&module.SMTP.TLSConfig)
		if err != nil {
			return nil, err
		}
		c, err = smtp.DialTLS(target, TLSConfig)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}
