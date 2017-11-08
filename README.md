# certstream-slack
[![Build Status](https://travis-ci.org/heptiolabs/certstream-slack.svg?branch=master)](https://travis-ci.org/heptiolabs/certstream-slack)
[![Go Report Card](https://goreportcard.com/badge/github.com/heptiolabs/certstream-slack)](https://goreportcard.com/report/github.com/heptiolabs/certstream-slack)

`certstream-slack` is a small daemon that watches your domains in [Certificate Transparency](https://www.certificate-transparency.org/what-is-ct) logs and posts them into [Slack](https://slack.com/). It uses the [API provided by Cali Dog Security](https://certstream.calidog.io/) rather than parsing the CT logs directly. Thanks to Cali Dog Security for this service!

## Usage

- Compile: `go install -v github.com/heptiolabs/certstream-slack`

- Run: `SLACK_WEBHOOK_URL='https://hooks.slack.com/services/[...]' DOMAIN_PATTERN='example' certstream-slack`

## Environment Variables

- **`SLACK_WEBHOOK_URL`**: a Slack [incoming webhook](https://api.slack.com/custom-integrations/incoming-webhooks) URL.
  The Slack configuration controls the name of the bot and the channel into which it will post.
  Leave this unset to skip posting to Slack (log only, useful for debugging).

- **`DOMAIN_PATTERN`**: A [Go regular expression](https://golang.org/pkg/regexp/syntax/).
  Certificates for domains that match this pattern will be posted to Slack.
  Consider watching your company's name and product names, for example: `(mycompany)|(myproduct1)|(myproduct2)`.
