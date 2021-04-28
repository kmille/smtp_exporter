package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-msgauth/authres"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	probeMessageReceived = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_message_received",
		Help: "Indicates if the message sent previously was received successfully",
	})

	probeSPFSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_spf_success",
		Help: "Indicates if SPF result is as expected",
	})

	probeDKIMSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dkim_success",
		Help: "Indicates if DKIM result is as expected",
	})

	probeDMARCSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dmarc_success",
		Help: "Indicates if DKIM result is as expected",
	})
)

// type ImapProberResult struct {
// 	// Commands contains all imap commands sent/received by the mail server
// 	Commands *bytes.Buffer
// 	Success  bool
// }

// func (i *ImapProberResult) Write(p []byte) (int, error) {
// 	// TODO: map this to imap
// 	if strings.HasPrefix(string(p), "AUTH PLAIN") {
// 		i.Commands.Write([]byte("AUTH PLAIN <secret>\r\n"))
// 	} else {
// 		i.Commands.Write(p)
// 	}
// 	return len(p), nil

// }

// func (i *ImapProberResult) String() string {
// 	return i.Commands.String()
// }

func IMAPReceiver(ctx context.Context, subject string, module config.IMAPReceiver, registry *prometheus.Registry, logger log.Logger) (success bool) {

	registry.MustRegister(probeMessageReceived)
	registry.MustRegister(probeSPFSuccess)
	registry.MustRegister(probeDKIMSuccess)
	registry.MustRegister(probeDMARCSuccess)

	// result := ImapProberResult{
	// 	Commands: &bytes.Buffer{},
	// 	Success:  false}

	newIMAPClient := func() (c *client.Client, err error) {

		targetIpPort := net.JoinHostPort(module.Server, fmt.Sprintf("%d", module.Port))
		level.Info(logger).Log("msg", "Connecting to IMAP server", "server", targetIpPort, "tls", module.TLS)

		ip, _, err := net.SplitHostPort(targetIpPort)
		if err != nil {
			return nil, err
		}
		var dialProtocol string
		if net.ParseIP(ip).To4() == nil {
			dialProtocol = "tcp6"
		} else {
			dialProtocol = "tcp4"
		}

		if strings.EqualFold(module.TLS, "no") ||
			strings.EqualFold(module.TLS, "starttls") {

			var d net.Dialer

			// BUG: tcp or tcp6, see: TCPProbe in blackbox_exporter
			conn, err := d.DialContext(ctx, dialProtocol, targetIpPort)
			if err != nil {
				return nil, err
			}

			deadline, _ := ctx.Deadline()
			if err = conn.SetDeadline(deadline); err != nil {
				return nil, err
			}

			c, err = client.New(conn)
			if err != nil {
				return nil, err
			}
			// c.SetDebug(result.Commands)

			if strings.EqualFold(module.TLS, "starttls") {
				tlsConfig, err := newTLSConfig(&module.TLSConfig)
				if err != nil {
					return nil, err
				}

				if err = c.StartTLS(tlsConfig); err != nil {
					return nil, err
				}
			}
		}

		if strings.EqualFold(module.TLS, "tls") {
			tlsConfig, err := newTLSConfig(&module.TLSConfig)
			if err != nil {
				return nil, err
			}

			var d tls.Dialer
			d.Config = tlsConfig
			conn, err := d.DialContext(ctx, dialProtocol, targetIpPort)
			if err != nil {
				return nil, err
			}

			deadline, _ := ctx.Deadline()
			if err = conn.SetDeadline(deadline); err != nil {
				return nil, err
			}

			c, err = client.New(conn)
			if err != nil {
				return nil, err
			}
			// c.SetDebug(result.Commands)
			// c.SetDebug(os.Stdout)
		}

		if c == nil {
			return nil, errors.New("could not create IMAP client")
		}
		level.Info(logger).Log("msg", "Successfully connected to IMAP server")
		return c, nil
	}

	c, err := newIMAPClient()
	if err != nil {
		level.Error(logger).Log("msg", "Error creating IMAP client", "err", err)
		return
	}

	defer c.Logout()

	if err := c.Login(module.Auth.Username, string(module.Auth.Password)); err != nil {
		level.Error(logger).Log("msg", "Error during IMAP login", "err", err)
		return
	}
	level.Error(logger).Log("msg", "IMAP authentication was successful")

	done := make(chan error, 1)
	if _, err = c.Select(module.Mailbox, true); err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("Error selecting mailbox %q", module.Mailbox), "err", err)
		return
	}
	searchCriteria := imap.NewSearchCriteria()
	filterHeaders := textproto.MIMEHeader{}
	filterHeaders.Set("Subject", subject)
	searchCriteria.Header = filterHeaders

	var seq []uint32
	for {
		if seq, err = c.Search(searchCriteria); err != nil {
			level.Error(logger).Log("msg", "Error searching for messages", "err", err)
			return
		}

		// this loop does not honor the Timeout
		if len(seq) == 0 {
			level.Debug(logger).Log("msg", "Message not yet found. Next retry in a second", "mailbox", module.Mailbox, "subject", subject)
			time.Sleep(1 * time.Second)
		} else {
			break
		}

	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(seq...)

	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem()}

	done = make(chan error, 1)
	messages := make(chan *imap.Message, 1)

	go func() {
		done <- c.Fetch(seqset, items, messages)
	}()
	msg := <-messages
	r := msg.GetBody(section)
	if r == nil {
		level.Error(logger).Log("msg", "Server did not return message body", "err", err)
		return
	}

	// BUG: wenn es zwei mails zu lesen gibt blocken wir hier, weil wir nur eine lesen!
	if err := <-done; err != nil {
		level.Error(logger).Log("msg", "Error fetching message", "err", err)
		return
	}

	m, err := mail.ReadMessage(r)
	if err != nil {
		level.Error(logger).Log("msg", "Could not read message", "err", err)
		return
	}

	level.Info(logger).Log("msg", "Found previously sent message in the mailbox", "subject", m.Header.Get("Subject"))
	probeMessageReceived.Set(1)

	// body, err := ioutil.ReadAll(m.Body)
	// if err != nil {
	// 	level.Error(logger).Log("msg", "Could not read body", "err", err)
	// 	return success
	// }

	// fmt.Printf("Body\n%s\n", body)

	authenticationResultsHeader := m.Header.Get("Authentication-Results")
	fmt.Println(authenticationResultsHeader)
	authenticationResultsNeeded := module.FailIfSPFNotMatches || module.FailIfDKIMNotMatches || module.FailIfDMARCNotMatches
	if authenticationResultsNeeded && len(authenticationResultsHeader) == 0 {
		level.Error(logger).Log("msg", "Message does not contain an Authentication-Results header")
		return
	}

	identifier, authenticationResults, err := authres.Parse(m.Header.Get("Authentication-Results"))
	fmt.Println(identifier)
	if err != nil {
		level.Error(logger).Log("msg", "Could not parse Authentication-Results header", "err", err)
		return
	}

	spfOK, dkimOK, dmarcOK := false, false, false

	for _, result := range authenticationResults {
		switch result.(type) {
		case *authres.SPFResult:
			spfResult := result.(*authres.SPFResult)
			level.Info(logger).Log("msg", "Checking SPF in Authentication-Results header", "result", spfResult.Value, "validResult", module.ValidSPFResult)
			if spfResult.Value == authres.ResultValue(module.ValidSPFResult) {
				probeSPFSuccess.Set(1)
				spfOK = true
			}
		case *authres.DKIMResult:
			dkimResult := result.(*authres.DKIMResult)
			level.Info(logger).Log("msg", "Checking DKIM in Authentication-Results header", "result", dkimResult.Value, "validResult", module.ValidDKIMResult)
			if dkimResult.Value == authres.ResultValue(module.ValidDKIMResult) {
				probeDKIMSuccess.Set(1)
				dkimOK = true
			}
		case *authres.DMARCResult:
			dmarcResult := result.(*authres.DMARCResult)
			level.Info(logger).Log("msg", "Checking DMARC in Authentication-Results header", "result", dmarcResult.Value, "validResult", module.ValidDKIMResult)
			if dmarcResult.Value == authres.ResultValue(module.ValidDMARCResult) {
				probeDMARCSuccess.Set(1)
				dmarcOK = true
			}
		}
	}

	if module.FailIfSPFNotMatches && !spfOK {
		level.Error(logger).Log("msg", "Probe failed. SPF result does not match", "spfOK", spfOK, "fail_if_spf_not_matches", module.FailIfSPFNotMatches)
		success = false
	} else if module.FailIfDKIMNotMatches && !dkimOK {
		level.Error(logger).Log("msg", "Probe failed. DKIM result does not match", "dkimOK", dkimOK, "fail_if_dkim_not_matches", module.FailIfDKIMNotMatches)
		success = false
	} else if module.FailIfDMARCNotMatches && !dmarcOK {
		level.Error(logger).Log("msg", "Probe failed. DMARC result does not match", "dmarcOK", dmarcOK, "fail_if_dmarc_not_matches", module.FailIfDMARCNotMatches)
		success = false
	} else {
		success = true
	}

	return
}
