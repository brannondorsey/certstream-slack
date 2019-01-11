/*
Copyright 2017 by the contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/CaliDog/certstream-go"
	slack "github.com/ashwanthkumar/slack-go-webhook"
	"github.com/dustin/go-humanize/english"
	"github.com/jmoiron/jsonq"
	"github.com/sirupsen/logrus"
)

func main() {
	// get the Slack webhook URL
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		logrus.Info("SLACK_WEBHOOK_URL not set, skipping Slack posting")
	}

	// get and compile the domain pattern regex
	domainPattern := os.Getenv("DOMAIN_PATTERN")
	if domainPattern == "" {
		logrus.Fatal("DOMAIN_PATTERN must be set")
	}
	domainRegex, err := regexp.Compile(domainPattern)
	if err != nil {
		logrus.WithError(err).Fatal("invalid DOMAIN_PATTERN")
	}

	logrus.WithField("domainPattern", domainRegex.String()).Info("watching for certificates")
	results, errors := certstream.CertStreamEventStream(true)
	for {
		select {
		case err := <-errors:
			logrus.WithError(err).Error("error streaming events")
		case jq := <-results:
			// we're only interested in "certificate_update" events
			if t, _ := jq.String("message_type"); t == "certificate_update" {
				handleCertificateUpdate(domainRegex, webhookURL, jq)
			}
		}
	}
}

func handleCertificateUpdate(domainRegex *regexp.Regexp, webhookURL string, jq jsonq.JsonQuery) {
	// pull the list of all the domains named in the leaf certificate (CN and SANs)
	domains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
	if err != nil {
		logrus.WithError(err).Error("couldn't get domains")
		return
	}

	domains = filter(domains, func(v string) bool {
		return !strings.Contains(v, "members.linode.com")
	})

	// if none of the domains match our regex, we're done
	if !anyMatch(domainRegex, domains) {
		return
	}

	// pull the certificate fingerprint and use it to get the crt.sh URL
	fingerprint, err := jq.String("data", "leaf_cert", "fingerprint")
	if err != nil {
		logrus.WithError(err).Error("could not parse fingerprint from matching certificate")
		return
	}
	certURL := fmt.Sprintf("https://crt.sh/?q=%s", strings.Replace(fingerprint, ":", "", -1))

	// post the Slack message
	payload := slack.Payload{
		Text: fmt.Sprintf(
			"A new certificate was created for %s: %s",
			formatDomainMessage(domainRegex, domains),
			certURL,
		),
	}

	logrus.Info(payload.Text)

	if webhookURL != "" {
		for _, err := range slack.Send(webhookURL, "", payload) {
			logrus.WithError(err).Error("error sending webhook")
		}
	}
}

func anyMatch(regex *regexp.Regexp, values []string) bool {
	for _, value := range values {
		if regex.MatchString(value) {
			return true
		}
	}
	return false
}

func formatDomainMessage(domainRegex *regexp.Regexp, domains []string) string {
	matches := []string{}
	for _, domain := range domains {
		if !domainRegex.MatchString(domain) {
			continue
		}
		// wrap each domain in backticks for a prettier Slack message
		matches = append(matches, "`"+domain+"`")
	}
	// report the matches in sorted order
	sort.Strings(matches)

	// generate a message like " and X others" if there are extra domains in
	// the cert that didn't match
	additionalDomains := len(domains) - len(matches)
	if additionalDomains > 0 {
		matches = append(matches, fmt.Sprintf("%d others", additionalDomains))
	}

	// join them together with an Oxford comma as required (!)
	return english.OxfordWordSeries(matches, "and")
}

// Returns a new slice containing all strings in the
// slice that satisfy the predicate `f`.
func filter(vs []string, f func(string) bool) []string {
	vsf := make([]string, 0)
	for _, v := range vs {
		if f(v) && len(v) > 7 {
			vsf = append(vsf, v)
		}
	}
	return vsf
}
