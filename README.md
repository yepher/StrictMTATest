# StrictMTATest

This is a quick test to verify STS configuration

This code is written to validate [STS-MTA](https://tools.ietf.org/html/draft-ietf-uta-mta-sts-10) configuration.


## Usage

```
StrictMTATest -help

Usage of ./StrictMTATest:
  -domain string
    	The domain to validate. Like gmail.com or comcast.net (default "gmail.com")

```


## Functionality

This project looks up the MX record for a given domain. It will then establish a TLS connection with each domain and validate it TLS configuration.

The tool also queries the TXT record for `_mta-sts.example.com` and verifies the format of the record returned is formed properly.

The tool queries `https://mta-sts.example.com/.well-known/mta-sts.txt` and verifies the content of the returned data.
