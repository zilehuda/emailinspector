emailinspector
=============

The `emailinspector` package is a Go library that allows you to inspect and validate email addresses. It provides various checks, including domain validation, disposable email detection, MX record validation, and blacklisting.

Installation
------------

To use the `emailinspector` package, you can install it using the `go get` command:

```shell
go get github.com/zilehuda/emailinspector
```

Usage
-----

Here's an example of how you can use the `emailinspector` package:

```go
package main

import (
	"fmt"
	"github.com/zilehuda/emailinspector"
)

func main() {
	email := "test@example.com"
	result := emailinspector.IsEmailValid(email)

	if result.IsValid {
		fmt.Println("The email is valid.")
	} else {
		fmt.Printf("The email is invalid. Reason: %s\n", result.Message)
	}
}
```

Functionality
-------------

- `IsEmailValid(email string) EmailInspectorResult`: This function validates the given email address and returns an `EmailInspectorResult` struct, which contains the validation result (`IsValid`) and an optional error message (`Message`).

- `IsValidEmail(email string) bool`: This function checks if the provided email address has a valid format based on a regular expression pattern.

- `HasValidMXRecords(domain string) bool`: This function checks if the domain of the email address has valid MX (Mail Exchange) records using the `net.LookupMX` function.

- `IsBlacklisted(domain string) bool`: This function checks if the domain of the email address is blacklisted using a list of DNSBL (DNS Blacklist) servers.

- `IsDisposableEmail(emailDomain string) bool`: This function checks if the domain of the email address is a known disposable domain.

Contributing
------------

Contributions to the `emailinspector` package are welcome! If you find any issues or have suggestions for improvement, please open an issue or submit a pull request on the GitHub repository.

License
-------

The `emailinspector` package is open source and available under the [MIT License](https://opensource.org/licenses/MIT).
