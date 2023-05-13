package emailinspector

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

var dnsblServers = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"cbl.abuseat.org",
	"dnsbl.sorbs.net",
}

type EmailInspectorResult struct {
	IsValid bool
	Message string
}

var disposableDomainFilePath = "disposable_domains.json"
var disposableDomains []string

func getDisposableDomains() *[]string {
	data, err := os.ReadFile(disposableDomainFilePath)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(data, &disposableDomains)
	if err != nil {
		panic(err)
	}
	return &disposableDomains

}

func IsDisposableEmail(emailDomain string) bool {
	domains := getDisposableDomains()
	for _, disposable := range *domains {
		if disposable == emailDomain {
			return true
		}
	}

	return false
}

func IsValidEmail(email string) bool {
	// Regular expression pattern for basic email address validation
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(pattern, email)
	return match
}

func HasValidMXRecords(domain string) bool {
	mxrecords, err := net.LookupMX(domain)
	for _, mx := range mxrecords {
		fmt.Println(mx.Host, mx.Pref)
	}

	return err == nil
}

func IsBlacklisted(domain string) bool {
	for _, server := range dnsblServers {
		query := fmt.Sprintf("%s.%s", domain, server)
		ips, err := net.LookupIP(query)
		fmt.Println(ips, err)
		if err == nil && len(ips) > 0 {
			return true
		}
	}
	return false
}

func IsEmailValid(email string) EmailInspectorResult {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return EmailInspectorResult{false, "Invalid email format"}
	}

	domain := parts[1]
	if IsDisposableEmail(domain) {
		return EmailInspectorResult{false, "Email address is disposable"}
	}

	if !IsValidEmail(email) {
		return EmailInspectorResult{false, "Invalid email format"}
	}

	if !HasValidMXRecords(domain) {
		return EmailInspectorResult{false, "Invalid MX records"}
	}

	if IsBlacklisted(domain) {
		return EmailInspectorResult{false, "Email address is blacklisted"}
	}

	return EmailInspectorResult{true, ""}
}
