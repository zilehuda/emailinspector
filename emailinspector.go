package emailinspector

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var dnsblServers = []string{
	"all.s5h.net",
	"b.barracudacentral.org",
	"bl.spamcop.net",
	"blacklist.woody.ch",
	"bogons.cymru.com",
	"cbl.abuseat.org",
	"combined.abuse.ch",
	"db.wpbl.info",
	"dnsbl-1.uceprotect.net",
	"dnsbl-2.uceprotect.net",
	"dnsbl-3.uceprotect.net",
	"dnsbl.dronebl.org",
	"dnsbl.sorbs.net",
	"drone.abuse.ch",
	"duinv.aupads.org",
	"dul.dnsbl.sorbs.net",
	"dyna.spamrats.com",
	"http.dnsbl.sorbs.net",
	"ips.backscatterer.org",
	"ix.dnsbl.manitu.net",
	"korea.services.net",
	"misc.dnsbl.sorbs.net",
	"noptr.spamrats.com",
	"orvedb.aupads.org",
	"pbl.spamhaus.org",
	"proxy.bl.gweep.ca",
	"psbl.surriel.com",
	"relays.bl.gweep.ca",
	"relays.nether.net",
	"sbl.spamhaus.org",
	"singular.ttk.pte.hu",
	"smtp.dnsbl.sorbs.net",
	"socks.dnsbl.sorbs.net",
	"spam.abuse.ch",
	"spam.dnsbl.anonmails.de",
	"spam.dnsbl.sorbs.net",
	"spam.spamrats.com",
	"spambot.bls.digibase.ca",
	"spamrbl.imp.ch",
	"spamsources.fabel.dk",
	"ubl.lashback.com",
	"ubl.unsubscore.com",
	"virus.rbl.jp",
	"web.dnsbl.sorbs.net",
	"wormrbl.imp.ch",
	"xbl.spamhaus.org",
	"z.mailspike.net",
	"zen.spamhaus.org",
	"zombie.dnsbl.sorbs.net",
}

type EmailInspectorResult struct {
	IsValid bool
	Message string
}

//go:embed disposable_domains.json
var disposableDomainData []byte

var disposableDomains []string

func getDisposableDomains() *[]string {
	if disposableDomains == nil {
		disposableDomains = loadDisposableDomains()
	}
	return &disposableDomains
}

func loadDisposableDomains() []string {
	var domains []string
	err := json.Unmarshal(disposableDomainData, &domains)
	if err != nil {
		panic(fmt.Errorf("failed to unmarshal disposable domain data: %w", err))
	}
	return domains
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
