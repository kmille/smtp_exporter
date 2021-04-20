package prober

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

type SmtpProberResult struct {
	// Commands contains all smtp commands sent/received by the mail server
	Commands *bytes.Buffer
	Success  bool
	Subject  string
}

func (s *SmtpProberResult) Write(p []byte) (int, error) {
	if strings.HasPrefix(string(p), "AUTH PLAIN") {
		s.Commands.Write([]byte("AUTH PLAIN <secret>\r\n"))
	} else {
		s.Commands.Write(p)
	}
	return len(p), nil

}

func (s *SmtpProberResult) String() string {
	return s.Commands.String()
}

func SmtpProber(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger) SmtpProberResult {

	var (
		statusCode         int
		statusCodeEnhanced int

		probeTLSVersion = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_tls_version_info",
				Help: "Contains the TLS version used",
			},
			[]string{"version"})

		probeIsTLSGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_smtp_tls",
			Help: "Indicates if TLS was used",
		})

		probeTLSCertExpireGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_tls_cert_expire",
			Help: "Returns the TLS cert expire in unixtime",
		})

		probeTLSInformation = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "probe_tls_info",
				Help: "Contains certificate information",
			},
			[]string{"fingerprint_sha256"})

		probeSmtpStatusCode = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_smtp_status_code",
			Help: "Response smtp status code",
		})

		probeSmtpEnhancedStatusCode = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_smtp_enhanced_status_code",
			Help: "Response smtp enhanced status code",
		})
	)

	result := SmtpProberResult{
		Commands: &bytes.Buffer{},
		Success:  false}

	registry.MustRegister(probeIsTLSGauge)
	registry.MustRegister(probeTLSCertExpireGauge)
	registry.MustRegister(probeSmtpStatusCode)
	registry.MustRegister(probeSmtpEnhancedStatusCode)

	handleSmtpError := func(c *smtp.Client, err error, msg string) {

		if c != nil {
			// if target port is closed, a client was never created
			if closeErr := c.Close(); closeErr != nil {
				level.Error(logger).Log("msg", "Error closing the connection", "err", err)
			}
		}

		smtpErr, ok := err.(*smtp.SMTPError)
		if !ok {
			// this is the case if we speak TLS to a non tls port
			level.Error(logger).Log("msg", msg, "err", err)
			statusCode = -1
			statusCodeEnhanced = -1
			return
		}
		statusCode = smtpErr.Code
		statusCodeEnhanced := smtpErr.EnhancedCode[0]*100 + smtpErr.EnhancedCode[1]*10 + smtpErr.EnhancedCode[2]
		level.Error(logger).Log("msg", msg, "err", err, "code", smtpErr.Code, "enhancedCode", statusCodeEnhanced)

		validStatusCodesPretty := strings.Join(strings.Split(fmt.Sprint(module.SMTP.ValidStatusCodes), " "), ",")
		level.Info(logger).Log("msg", "Checking valid status codes", "validStatusCodes", validStatusCodesPretty)
		for _, validStatusCode := range module.SMTP.ValidStatusCodes {
			if validStatusCode == smtpErr.Code {
				result.Success = true
			}
		}
	}

	newSmtpClient := func(targetIpPort string) (c *smtp.Client, err error) {

		if strings.EqualFold(module.SMTP.TLS, "no") ||
			strings.EqualFold(module.SMTP.TLS, "starttls") {

			var d net.Dialer
			conn, err := d.DialContext(ctx, "tcp", targetIpPort)
			if err != nil {
				return nil, fmt.Errorf("could not connect to target: %s", err)
			}

			c, err = smtp.NewClient(conn, "")
			if err != nil {
				return nil, err
			}
			c.DebugWriter = result.Commands

			if err = ehlo(c, module); err != nil {
				return nil, err
			}

			if strings.EqualFold(module.SMTP.TLS, "starttls") {
				tlsConfig, err := newTLSConfig(&module.SMTP.TLSConfig)
				if err != nil {
					return nil, err
				}
				if err = c.StartTLS(tlsConfig); err != nil {
					return nil, err
				}
			}
		}

		if strings.EqualFold(module.SMTP.TLS, "tls") {

			var d tls.Dialer
			conn, err := d.DialContext(ctx, "tcp", targetIpPort)
			if err != nil {
				return nil, fmt.Errorf("could not connect to target: %s", err)
			}

			tlsConfig, err := newTLSConfig(&module.SMTP.TLSConfig)
			if err != nil {
				return nil, err
			}
			d.Config = tlsConfig

			c, err = smtp.NewClient(conn, "")
			if err != nil {
				return nil, err
			}

			c.DebugWriter = result.Commands
			if err = ehlo(c, module); err != nil {
				return nil, err
			}
		}

		if c == nil {
			level.Info(logger).Log("error", "TODO:// this should not happend")
			return nil, errors.New("TOO")
		}
		level.Info(logger).Log("msg", "Successfully connected to smtp server", "server", targetIpPort, "tls", module.SMTP.TLS)
		return c, nil
	}

	// target is the value of the GET parameter sent by Prometheus
	targetHost, targetPort, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse target", "err", err)
		return result
	}

	ip, lookupTime, err := chooseProtocol(ctx, module.SMTP.IPProtocol, module.SMTP.IPProtocolFallback, targetHost, registry, logger)
	fmt.Println(lookupTime)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return result
	}

	if len(module.SMTP.TLSConfig.ServerName) == 0 {
		module.SMTP.TLSConfig.ServerName = targetHost
	}

	c, err := newSmtpClient(net.JoinHostPort(ip.String(), targetPort))
	if err != nil {
		handleSmtpError(c, err, "Error creating smtp client")
		return result
	}

	defer func() {
		probeSmtpStatusCode.Set(float64(statusCode))
		probeSmtpEnhancedStatusCode.Set(float64(statusCodeEnhanced))
	}()

	state, ok := c.TLSConnectionState()
	if ok {
		registry.MustRegister(probeTLSVersion, probeTLSInformation)
		probeIsTLSGauge.Set(1)
		probeTLSVersion.WithLabelValues(getTLSVersion(&state)).Set(1)
		// TODO: check if this calculation is valid
		probeTLSCertExpireGauge.Set(float64(getCertExpiry(&state).Unix()))
		probeTLSInformation.WithLabelValues(getFingerprint(&state)).Set(1)
	}

	if len(module.SMTP.Auth.Username) > 0 {
		auth := sasl.NewPlainClient("", module.SMTP.Auth.Username, string(module.SMTP.Auth.Password))
		if err = c.Auth(auth); err != nil {
			handleSmtpError(c, err, "Error sending AUTH command")
			return result
		}
		level.Info(logger).Log("msg", "Authentication was successful")
	} else {
		level.Info(logger).Log("msg", "Skipping authentication (not configured)")
	}

	if err = c.Mail(module.SMTP.MailFrom, nil); err != nil {
		handleSmtpError(c, err, "Error sending MAIL FROM command")
		return result
	}
	level.Info(logger).Log("msg", "MAIL FROM command sent successfully")

	if err = c.Rcpt(module.SMTP.MailTo); err != nil {
		handleSmtpError(c, err, "Error sending RCPT TO command")
		return result
	}
	level.Info(logger).Log("msg", "RCPT TO command sent successfully")

	w, err := c.Data()
	if err != nil {
		handleSmtpError(c, err, "Error sending DATA command")
		return result
	}

	message, subject := buildMessage(module)
	result.Subject = subject

	if _, err = w.Write([]byte(message)); err != nil {
		level.Error(logger).Log("msg", "Error sending email data ", "err", err)
	}

	if err = w.Close(); err != nil {
		level.Error(logger).Log("msg", "Error closing the email buffer", "err", err)
	}

	if err = c.Quit(); err != nil {
		handleSmtpError(c, err, "Error sending QUIT command")
		return result
	}

	level.Info(logger).Log("msg", "Mail successfully sent", "subject", result.Subject)

	result.Success = true
	statusCode = 221
	statusCodeEnhanced = 200
	return result
}

func ehlo(c *smtp.Client, module config.Module) error {
	err := c.Hello(module.SMTP.EHLO)
	if err != nil {
		return err
	}
	return nil
}

func buildMessage(module config.Module) (string, string) {

	body := module.SMTP.Body
	if len(body) == 0 {
		body = "This is a test mail sent by the smtp_exporter"
	}

	headers := make(map[string]string)
	for k, v := range module.SMTP.Headers {
		headers[k] = v
	}

	_, ok := headers["subject"]
	if !ok {
		headers["subject"] = "[smtp_exporter]"
	}

	headers["subject"] = fmt.Sprintf("%s %s", headers["subject"], uuid.New().String())
	headers["Message-ID"] = generateMessageID()

	// now := time.Now().Format("Tue, 6 Apr 2021 13:33:16 +0200")
	// now := time.Now().Format("Mon, Jan 2 15:04:05 MST 2006")
	now := time.Now().Format("Wed, 07 Apr 2021 13:53:34")
	// TODO: get the date format right oO
	// https://tools.ietf.org/html/rfc2822#section-3.3

	headers["Date"] = now
	// fmt.Println(now)

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body
	return message, headers["subject"]
}
