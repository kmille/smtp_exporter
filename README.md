**Unfortunately, this one of these almost-done-but-never-released projects. I like it, it works in general but it needs some love to get the last TODOs done. It's open source, so feel free to get in touch with the code. If you're familiar with go, it's not that hard :)**

[![Go tests for smtp_exporter](https://github.com/kmille/smtp_exporter/actions/workflows/tests.yaml/badge.svg)](https://github.com/kmille/smtp_exporter/actions/workflows/tests.yaml)

# smtp_exporter 

smtp_exporter is a Prometheus Exporter for testing your outgoing mail server. It's internal design and usage is very similar to [blackbox_exporter](https://github.com/prometheus/blackbox_exporter). There is currently only one Prober (smtp). Check the outstanding [TODOs](/TODO) for more information. You can reload the configuration with a post request to /-/reload. There is also a history log like you know it from blackbox_exporter.

# How to use it

```bash
kmille@linbox:smtp_exporter go run ./main.go ./history.go --web.listen-address="127.0.0.1:9125" --log.level=debug --config.file=smtp.yml
```

# What you can test

### Can I sent an authenticated mail (starttls)?

```yaml
  smtp_starttls_authentication_ok:
    prober: smtp
    smtp:
      preferred_ip_protocol: ip4 
      tls: starttls
      auth:
           username: mail-test1@androidloves.me
           password: mail-test-1password
      headers:
        from: mail-test1@androidloves.me
        to: mail-test2@androidloves.me
```

The output contains also information about the encryption (tls version, certificate validation, certificate expiration date). [Debug Output](metric_examples/smtp_starttls_authentication_ok.txt)

### Can I sent an authenticated mail over ipv6 (tls)?

```yaml
  smtp_tls_authentication_ok_ipv6:
    prober: smtp
    smtp:
      preferred_ip_protocol: ip6
      ip_protocol_fallback: false
      tls: tls
      ehlo: smtp01.wurbz.de
      mail_from: kmille@darmstadt.ccc.de
      mail_to: mail-test2@androidloves.me
      auth:
           username: kmille
           password: ccc-password
      headers:
        from: kmille@darmstadt.ccc.de
        to: mail-test2@androidloves.me
        subject: mail-monitoring
      body: This mail was sent over ipv6
```

You can specify ehlo, mail_from, mail_to, message headers. [Debug Output](metric_examples/smtp_tls_authentication_ok_ipv6.txt)

### Is our mail delivered by the receiving mail server?

```yaml
  smtp_starttls_imap_receiver:
    prober: smtp
    smtp:
      preferred_ip_protocol: ip4
      tls: starttls
      auth:
           username: mail-test1@androidloves.me
           password: mail-test-1password
      headers:
        from: mail-test1@androidloves.me
        to: mail-test2@androidloves.me
      receiver: imap
      imap:
        tls: tls
        auth:
             username: mail-test2@androidloves.me
             password: mail-test-1password
        mailbox: INBOX
        server: beeftraeger.wurbz.de
        port: 993
```

Every message the smtp_exporter sends contains a unique id in the subject. We can search for it in the mailbox using IMAP. [Debug Output](metric_examples/smtp_starttls_imap_receiver.txt)

### Can I login with disabled credentials?

```yaml
  smtp_tls_authentication_wrong:
    prober: smtp
    smtp:
      tls: tls
      auth:
        username: mail-test1@androidloves.me
        password: thisisnotavalidpassword
      valid_status_codes:
      - 535
```

You can check for a list of SMTP status codes. [Debug Output](metric_examples/smtp_tls_authentication_wrong.txt)

### Is authentication enabled without encryption?

```yaml
  smtp_plain_authentication_not_available:
    prober: smtp
    smtp:
      auth:
        username: mail-test1@androidloves.me
        password: thiswontwork
     valid_status_codes:
      - 530
```

`tls` can have the values `no`,`starttls` and  `tls`. If no value is set no encryption is used. [Debug Output](metric_examples/smtp_plain_authentication_not_available.txt)

### Can I forge email addresses (specify arbitrary from values) after authentication?

```yaml
  smtp_starttls_auth_ok_forged_from:
    prober: smtp
    smtp:
      tls: starttls
      auth:
           username: mail-test1@androidloves.me
           password: mail-test-1password
      headers:
        from: angela@merkel.de
        to: mail-test1@androidloves.me
        subject: test message
      body: I'm not authenticated to write emails as this user
      valid_status_codes:
      - 553
```

[Debug Output](metric_examples/smtp_starttls_auth_ok_forged_from.txt)

### Do you accept mails without authentication (open relay?)

```yaml
  smtp_starttls_open_relay:
    prober: smtp
    smtp:
      tls: starttls
      headers:
        from: mail-test1@androidloves.me
        to: test@google.de
        body: This mail should be rejected because we are not authenticated.
      valid_status_codes:
      - 454
```

[Debug Output](metric_examples/smtp_starttls_open_relay.txt)

### Do you reject mails if I'm not authorized to send mails as google.com?

```yaml
  smtp_starttls_spam_message_rejected:
    prober: smtp
    smtp:
      headers:
        from: angela@google.com
        to: mail-test2@androidloves.me
      body: This mail should be rejected because the we are not authorized to send mail as google.com
      valid_status_codes:
      - 554
```

[Debug Output](metric_examples/smtp_starttls_spam_message_rejected.txt)
