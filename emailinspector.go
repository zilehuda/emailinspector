package emailinspector

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
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
	_, err := net.LookupMX(domain)
	return err == nil
}

func IsBlacklisted(domain string) bool {
	for _, server := range dnsblServers {
		query := fmt.Sprintf("%s.%s", domain, server)
		ips, err := net.LookupIP(query)
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

	wg := &sync.WaitGroup{}
	chanRes := make(chan EmailInspectorResult, 4)

	wg.Add(4)
	go func() {
		defer wg.Done()
		if IsDisposableEmail(domain) {
			chanRes <- EmailInspectorResult{false, "Email address is disposable"}
		}
	}()

	go func() {
		defer wg.Done()
		if !IsValidEmail(email) {
			chanRes <- EmailInspectorResult{false, "Invalid email format"}
		}
	}()

	go func() {
		defer wg.Done()
		if !HasValidMXRecords(domain) {
			chanRes <- EmailInspectorResult{false, "Invalid MX records"}
		}
	}()

	go func() {
		defer wg.Done()
		if IsBlacklisted(domain) {
			chanRes <- EmailInspectorResult{false, "Email address is blacklisted"}
		}
	}()

	wg.Wait()
	close(chanRes)

	for result := range chanRes {
		if !result.IsValid {
			return result
		}
	}

	return EmailInspectorResult{true, ""}
}
