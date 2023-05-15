package emailinspector

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsDisposableEmail(t *testing.T) {

	// Test with disposable email domain
	disposableDomain := "bugfoo.com"
	result := IsDisposableEmail(disposableDomain)
	fmt.Println("her: ", result)
	assert.True(t, result, "Expected %s to be a disposable email domain", disposableDomain)

	// Test with non-disposable email domain
	nonDisposableDomain := "gmail.com"
	result = IsDisposableEmail(nonDisposableDomain)
	assert.False(t, result, "Expected %s to not be a disposable email domain", nonDisposableDomain)

}

func TestHasValidMXRecords(t *testing.T) {
	// Test with domain having valid MX records
	domainWithMX := "gmail.com"
	result := HasValidMXRecords(domainWithMX)
	assert.True(t, result, "Expected %s to have valid MX records", domainWithMX)

	// Test with domain having no MX records
	domainWithoutMX := "invalid.domain"
	result = HasValidMXRecords(domainWithoutMX)
	assert.False(t, result, "Expected %s to have no MX records", domainWithoutMX)

}

// TODO: need to implement with mocking
//func TestIsBlacklisted(t *testing.T) {}

func TestIsEmailValid(t *testing.T) {
	// Test with a valid email
	validEmail := "test@example.com"
	result := IsEmailValid(validEmail)
	assert.True(t, result.IsValid, "Expected valid email to be valid")
	assert.Empty(t, result.Message, "Expected valid email to have an empty message")

	// Test with an invalid email format
	invalidEmail := "invalid_email"
	result = IsEmailValid(invalidEmail)
	assert.False(t, result.IsValid, "Expected invalid email format to be invalid")
	assert.Equal(t, "Invalid email format", result.Message, "Expected invalid email format message")

	// Test with a disposable email
	disposableEmail := "test@bugfoo.com"
	result = IsEmailValid(disposableEmail)
	assert.False(t, result.IsValid, "Expected disposable email to be invalid")
	assert.Equal(t, "Email address is disposable", result.Message, "Expected disposable email message")

	// Test with an email with invalid MX records
	invalidMXEmail := "test@invalid.domain"
	result = IsEmailValid(invalidMXEmail)
	assert.False(t, result.IsValid, "Expected email with invalid MX records to be invalid")
	assert.Equal(t, "Invalid MX records", result.Message, "Expected invalid MX records message")

	//TODO: Test with a blacklisted email

}
