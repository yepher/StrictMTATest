/**
* This is a tool is used to validate configuration for
* SMTP MTA Strict Transport Security (MTA-STS)
*
*
* This code validates against Draft v10
*     https://tools.ietf.org/html/draft-ietf-uta-mta-sts-10
*
**/
package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
)

func main() {
	domain := flag.String("domain", "gmail.com", "The domain to validate. Like gmail.com or comcast.net")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Domain is a required field\n\n ")
		flag.PrintDefaults()
		os.Exit(1)
	}

	mxRecords := mxRecords(*domain)
	for _, record := range mxRecords {
		if len(record) > 0 {
			tlsTest(record, "25")
		}
	}

	// Do DNS txt check
	stsRecord := stsDNSCheck("_mta-sts." + *domain)
	if len(stsRecord) > 0 {
		fmt.Printf("STS Found. STS Record:\n\t %s\n\n", stsRecord)
	} else {
		fmt.Printf("ERROR: STS Failed, DNS record not found\n\n")
	}

	// HTTP lookup
	policyResource := queryHTTPSRecord("https://mta-sts." + *domain + "/.well-known/mta-sts.txt")
	policyRows := strings.Split(policyResource, "\n")

	// Validate policy resource records
	if !hasKey(policyRows, "version") {
		fmt.Println("Error the policy resource must contain a version field")
	}

	if valueForKey(policyRows, "version") != "STSv1" {
		fmt.Println("Error version must equal 'STSv1'")
	}

	mode := valueForKey(policyRows, "mode")
	if mode != "report" && mode != "enforce" && mode != "none" {
		fmt.Printf("Error mode must be one of 'report', 'enforce', 'none' but was %s", mode)
	}

	if !hasKey(policyRows, "max_age") {
		fmt.Printf("Error policy resource should have a 'max_age' field.")
	}

	allKeys := allKeys(policyRows)
	for _, key := range allKeys {
		if key != "" && key != "version" && key != "mode" && key != "max_age" && key != "mx" {
			fmt.Printf("Error unknown key in policy [%s]\n", key)
		}
	}

	mxs := valuesForKey(policyRows, "mx")
	for _, record := range mxRecords {
		if len(record) > 0 {
			if !mxHasMatch(mxs, record) {
				fmt.Printf("Error undefined MX record [%s]\n", record)
			}
		}
	}

}

func mxHasMatch(declaredMXs []string, mxHost string) bool {
	for _, mx := range declaredMXs {
		if strings.HasPrefix(mx, ".") {
			i := strings.Index(mxHost, ".")
			baseHost := mxHost[i:]
			if baseHost == mx {
				return true
			}

		} else if mx == mxHost {
			return true
		}
	}
	return false
}

func hasKey(rows []string, key string) bool {
	for _, line := range rows {
		if strings.HasPrefix(line, key) {
			return true
		}
	}
	return false
}

// Returns first value that has given key
func valueForKey(rows []string, key string) string {
	for _, line := range rows {
		if strings.HasPrefix(line, key) {
			fields := strings.Split(line, ":")
			return strings.TrimSpace(fields[1])
		}
	}
	return ""
}

func valuesForKey(rows []string, key string) []string {
	results := make([]string, 1, 4)
	for _, line := range rows {
		if strings.HasPrefix(line, key) {
			fields := strings.Split(line, ":")
			value := strings.TrimSpace(fields[1])
			results = append(results, value)
		}
	}
	return results
}

func allKeys(rows []string) []string {
	keys := make([]string, 1, 4)

	for _, line := range rows {
		fields := strings.Split(line, ":")
		key := strings.TrimSpace(fields[0])
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func mxRecords(domain string) []string {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		log.Fatal(err)
	}

	records := make([]string, 1, 4)
	for _, mx := range mxs {
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "%s", mx.Host)
		records = append(records, normalizeDomain(buf.String()))
	}
	return records
}

func stsDNSCheck(domain string) string {
	txt, err := net.LookupTXT(domain)
	if err != nil {
		fmt.Println(err)
	} else {
		// If we get multiple TXT records ours starts with "v=STSv1;"
		// See: https://tools.ietf.org/html/draft-ietf-uta-mta-sts-10#section-3.1
		for _, element := range txt {
			if strings.HasPrefix(element, "v=STSv1; ") {
				return element
			}
		}
	}
	return ""
}

func tlsTest(host string, port string) {

	smtpserver := host + ":" + port
	//fmt.Printf("Tesing: %s\n", smtpserver)

	config := &tls.Config{ServerName: host}

	c, err := smtp.Dial(smtpserver)
	if err != nil {
		log.Printf("Could not connect to %s:%s\n", host, port)
		log.Printf("\x1b[31;1mError\x1b[0m  \"%v\"\n", err)
		return
	}

	err = c.StartTLS(config)
	if err != nil {
		errorMsg := fmt.Sprintf("\x1b[31;1mError:\x1b[0m [%s:%s] failed with error message\n\t\x1b[31;1m%s %s\x1b[0m", host, port, host, err)

		log.Println(errorMsg)
	} else {
		log.Println("✔ ", host, " certificate is good")
	}

}

func queryHTTPSRecord(url string) string {
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	} else {
		defer response.Body.Close()
		responseData, err := ioutil.ReadAll(response.Body)
		if err != nil {
			fmt.Println("STS Failed HTTPS record not found")
			log.Fatal(err)
		} else {
			fmt.Println("STS HTTPS Record:\n------------------")
			responseString := string(responseData)
			fmt.Println(responseString)
			return responseString
		}
	}
	return ""
}

func normalizeDomain(domain string) string {
	if strings.HasSuffix(domain, ".") {
		return trimSuffix(domain, ".")
	}

	return domain
}

func trimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}
