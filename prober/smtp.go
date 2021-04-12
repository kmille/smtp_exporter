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

	sasl "github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	pconfig "github.com/prometheus/common/config"
)

func SmtpProber(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger log.Logger, hl *HistoryLog) bool {

	// TODO: move this to config.go and check it if the module is loaded
	mailFrom := module.SMTP.MailFrom
	if len(mailFrom) == 0 {
		mailFrom = module.SMTP.Headers["from"]
		// var ok bool
		// mailFrom, ok = module.SMTP.Headers["from"]
		// if !ok {
		// 	level.Error(logger).Log("msg", "Error parsing module configuration. MailFrom not found")
		// 	return false
		// }
	}

	mailTo := module.SMTP.MailTo
	if len(mailTo) == 0 {
		mailTo = module.SMTP.Headers["to"]
		// var ok bool
		// TODO: does this work with TO, To?
		// mailTo, ok = module.SMTP.Headers["to"]
		// if !ok {
		// 	level.Error(logger).Log("msg", "Error parsing module configuration. MailTo not found")
		// 	return false
		// }
	}

	// mailFrom := module.SMTP.MailFrom
	// mailTo := module.SMTP.MailTo

	var (
		statusCode         int
		statusCodeEnhanced int
		success            bool

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

	handleSmtpError := func(c *smtp.Client, err error, msg string) {
		closeErr := c.Close()
		if closeErr != nil {
			level.Error(logger).Log("msg", "Error closing the connection", "err", err)
		}

		smtpErr, ok := err.(*smtp.SMTPError)
		if !ok {
			// this is the case if we speak TLS to a non tls port
			level.Error(logger).Log("msg", msg, "err", err)
			statusCode = -1
			statusCodeEnhanced = -1
			success = false
			return
		}
		smtpEnhancedCode := smtpErr.EnhancedCode[0]*100 + smtpErr.EnhancedCode[1]*10 + smtpErr.EnhancedCode[2]
		level.Error(logger).Log("msg", msg, "err", err, "code", smtpErr.Code, "enhancedCode", smtpEnhancedCode)
		// probeSmtpStatusCode.Set(float64(smtpErr.Code))
		// probeSmtpEnhancedStatusCode.Set(float64(smtpEnhancedCode))

		validStatusCodes := strings.Join(strings.Split(fmt.Sprint(module.SMTP.ValidStatusCodes), " "), ",")
		level.Info(logger).Log("msg", "Checking valid status codes", "validStatusCodes", validStatusCodes)
		for _, validStatusCode := range module.SMTP.ValidStatusCodes {
			if validStatusCode == smtpErr.Code {
				statusCode = smtpErr.Code
				statusCodeEnhanced = smtpEnhancedCode
				success = true
			}
		}
	}

	historyLog := NewHistoryLog()

	NewSmtpClient := func(targetIpPort, serverName string) (c *smtp.Client, err error) {

		if len(module.SMTP.TLS) == 0 ||
			module.SMTP.TLS == "no" ||
			module.SMTP.TLS == "starttls" {

			c, err = smtp.Dial(targetIpPort)
			if err != nil {
				return nil, err
			}

			c.DebugWriter = historyLog
			err = ehlo(c, serverName, module)
			if err != nil {
				return nil, err
			}

			if module.SMTP.TLS == "starttls" {
				tlsConfig, err := NewSmtpTlsConfig(serverName, module, logger)
				if err != nil {
					return nil, err
				}
				err = c.StartTLS(tlsConfig)
				if err != nil {
					return nil, err
				}
			}
		}

		if module.SMTP.TLS == "tls" {
			tlsConfig, err := NewSmtpTlsConfig(serverName, module, logger)
			if err != nil {
				return nil, err
			}

			c, err = smtp.DialTLS(targetIpPort, tlsConfig)
			if err != nil {
				return nil, err
			}

			c.DebugWriter = historyLog
			err = ehlo(c, serverName, module)
			if err != nil {
				return nil, err
			}
		}

		if c == nil {
			level.Info(logger).Log("error", "TODO:// this should not happend")
			return nil, errors.New("TOO")
		}
		level.Info(logger).Log("msg", "Successfully connected to the smtp server", "tls", module.SMTP.TLS)
		return c, nil
	}

	registry.MustRegister(probeIsTLSGauge)
	registry.MustRegister(probeTLSCertExpireGauge)
	registry.MustRegister(probeSmtpStatusCode)
	registry.MustRegister(probeSmtpEnhancedStatusCode)

	targetHost, targetPort, err := net.SplitHostPort(target)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse target", "err", err)
		return false
	}

	ip, lookupTime, err := chooseProtocol(ctx, module.SMTP.IPProtocol, module.SMTP.IPProtocolFallback, targetHost, registry, logger)
	fmt.Println(lookupTime)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}

	serverName := module.SMTP.TLSConfig.ServerName
	if len(serverName) == 0 {
		serverName = targetHost
	}

	c, err := NewSmtpClient(net.JoinHostPort(ip.String(), targetPort), serverName)
	if err != nil {
		handleSmtpError(c, err, "Error creating smtp client")
		return success
	}

	defer func() {
		// probeSmtpStatusCode.Set(float64(221))
		// probeSmtpEnhancedStatusCode.Set(float64(200))

		probeSmtpStatusCode.Set(float64(statusCode))
		probeSmtpEnhancedStatusCode.Set(float64(statusCodeEnhanced))
		fmt.Printf("Let's print the history\n%s", historyLog.buf.String())
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
		auth := sasl.NewPlainClient("", module.SMTP.Auth.Username, module.SMTP.Auth.Password)
		if err = c.Auth(auth); err != nil {
			handleSmtpError(c, err, "Error sending AUTH command")
			return success
		}
		level.Info(logger).Log("msg", "Authenticated was successful")
	} else {
		level.Info(logger).Log("msg", "Skipping authentication (not configured)")
	}

	if err = c.Mail(mailFrom, nil); err != nil {
		handleSmtpError(c, err, "Error sending MAIL FROM command")
		return success
	}
	level.Info(logger).Log("msg", "MAIL FROM command sent successfully")

	if err = c.Rcpt(mailTo); err != nil {
		handleSmtpError(c, err, "Error sending RCPT TO command")
		return success
	}
	level.Info(logger).Log("msg", "RCPT TO command sent successfully")

	w, err := c.Data()
	if err != nil {
		handleSmtpError(c, err, "Error sending DATA command")
		return success
	}

	headers := make(map[string]string)
	for k, v := range module.SMTP.Headers {
		headers[k] = v
	}

	_, ok = headers["subject"]
	if !ok {
		headers["subject"] = "smtp_exporter email monitoring"
	}

	headers["Message-ID"] = generateMessageID()
	// now := time.Now().Format("Tue, 6 Apr 2021 13:33:16 +0200")
	// now := time.Now().Format("Mon, Jan 2 15:04:05 MST 2006")
	now := time.Now().Format("Wed, 07 Apr 2021 13:53:34")
	// TODO: get the date format right oO
	// https://tools.ietf.org/html/rfc2822#section-3.3

	headers["Date"] = now
	// fmt.Println(now)

	body := module.SMTP.Body
	if len(body) == 0 {
		body = "This is a test mail sent by the smtp_exporter"
	}

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body

	_, err = w.Write([]byte(message))
	if err != nil {
		level.Error(logger).Log("msg", "Error sinding email data ", "err", err)
	}
	err = w.Close()
	if err != nil {
		level.Error(logger).Log("msg", "Error closing the email buffer", "err", err)
	}

	err = c.Quit()
	if err != nil {
		handleSmtpError(c, err, "Error sending QUIT command")
		return false
	}

	success = true

	return success
}

func NewSmtpTlsConfig(serverName string, module config.Module, logger log.Logger) (*tls.Config, error) {
	tlsConfig, err := pconfig.NewTLSConfig(&module.SMTP.TLSConfig)
	if err != nil {
		return nil, err
	}
	if len(tlsConfig.ServerName) == 0 {
		tlsConfig.ServerName = serverName
	}
	return tlsConfig, nil
}

func ehlo(c *smtp.Client, serverName string, module config.Module) error {

	ehlo := module.SMTP.EHLO
	if len(ehlo) == 0 {
		ehlo = serverName
	}
	err := c.Hello(ehlo)
	if err != nil {
		return err
	}
	return nil
}

type HistoryLog struct {
	buf *bytes.Buffer
}

func NewHistoryLog() *HistoryLog {
	return &HistoryLog{buf: bytes.NewBuffer([]byte(""))}
}

func (hl *HistoryLog) Write(p []byte) (int, error) {
	lenData := len(p)
	if strings.HasPrefix(string(p), "AUTH PLAIN") {
		p = []byte("AUTH PLAIN *******************\r\n")
	}
	hl.buf.Write(p)
	return lenData, nil
}

func (hl *HistoryLog) String() string {
	return hl.buf.String()
}
