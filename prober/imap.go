package prober

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/kmille/smtp_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

type ImapProberResult struct {
	// Commands contains all imap commands sent/received by the mail server
	Commands *bytes.Buffer
	Success  bool
}

func (i *ImapProberResult) Write(p []byte) (int, error) {
	// TODO: map this to imap
	if strings.HasPrefix(string(p), "AUTH PLAIN") {
		i.Commands.Write([]byte("AUTH PLAIN <secret>\r\n"))
	} else {
		i.Commands.Write(p)
	}
	return len(p), nil

}

func (i *ImapProberResult) String() string {
	return i.Commands.String()
}

func ImapProber(ctx context.Context, subject string, module config.Module, registry *prometheus.Registry, logger log.Logger) ImapProberResult {

	result := ImapProberResult{
		Commands: &bytes.Buffer{},
		Success:  false}

	newImapClient := func() (c *client.Client, err error) {

		targetIpPort := net.JoinHostPort(module.IMAP.Server, fmt.Sprintf("%d", module.IMAP.Port))
		level.Info(logger).Log("msg", "Connecting to imap server", "server", targetIpPort, "tls", module.IMAP.TLS)

		if strings.EqualFold(module.IMAP.TLS, "no") ||
			strings.EqualFold(module.IMAP.TLS, "starttls") {

			c, err = client.Dial(targetIpPort)
			if err != nil {
				return nil, err
			}
			c.SetDebug(result.Commands)

			if strings.EqualFold(module.IMAP.TLS, "starttls") {
				tlsConfig, err := newTLSConfig(&module.IMAP.TLSConfig)
				if err != nil {
					return nil, err
				}

				if err = c.StartTLS(tlsConfig); err != nil {
					return nil, err
				}
			}
		}

		if strings.EqualFold(module.IMAP.TLS, "tls") {
			tlsConfig, err := newTLSConfig(&module.IMAP.TLSConfig)
			if err != nil {
				return nil, err
			}

			c, err = client.DialTLS(targetIpPort, tlsConfig)
			if err != nil {
				return nil, err
			}
			c.SetDebug(result.Commands)
		}

		if c == nil {
			return nil, errors.New("smtp client object is still nil")
		}
		level.Info(logger).Log("msg", "Successfully connected to IMAP server")
		return c, nil
	}

	c, err := newImapClient()
	if err != nil {
		level.Error(logger).Log("msg", "Error connecting to IMAP server", "err", err)
		return result
	}

	defer c.Logout()

	if err := c.Login(module.IMAP.Auth.Username, string(module.IMAP.Auth.Password)); err != nil {
		level.Error(logger).Log("msg", "Error during IMAP login", "err", err)
		return result
	}

	done := make(chan error, 1)
	if _, err = c.Select(module.IMAP.Mailbox, true); err != nil {
		level.Error(logger).Log("msg", fmt.Sprintf("Error selecting mailbox %q", module.IMAP.Mailbox), "err", err)
		return result
	}

	searchCriteria := imap.NewSearchCriteria()
	filterHeaders := textproto.MIMEHeader{}
	filterHeaders.Set("Subject", subject)
	searchCriteria.Header = filterHeaders

	var seq []uint32
	for {
		if seq, err = c.Search(searchCriteria); err != nil {
			level.Error(logger).Log("msg", "Error searching for messages", "err", err)
			return result
		}

		if len(seq) == 0 {
			level.Error(logger).Log("msg", "Message not found. Retry in a second", "mailbox", module.IMAP.Mailbox, "subject", subject)
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
		level.Error(logger).Log("msg", "Server didn't returned message body", "err", err)
		return result
	}

	if err := <-done; err != nil {
		level.Error(logger).Log("msg", "Error fetching message", "err", err)
		return result
	}

	m, err := mail.ReadMessage(r)
	if err != nil {
		level.Error(logger).Log("msg", "Could not read message", "err", err)
		return result
	}

	// body, err := ioutil.ReadAll(m.Body)
	// if err != nil {
	// 	level.Error(logger).Log("msg", "Could not read body", "err", err)
	// 	return success
	// }

	// fmt.Printf("Body\n%s\n", body)

	level.Info(logger).Log("msg", "Found previously sent mail in the mailbox", "subject", m.Header.Get("Subject"))
	result.Success = true

	return result
}
