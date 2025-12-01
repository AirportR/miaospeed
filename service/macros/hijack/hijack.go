package hijack

import (
	"github.com/airportr/miaospeed/interfaces"
	"github.com/airportr/miaospeed/vendors"
	"regexp"
)

const CheckUrlGoogle = "https://ipv4.google.com/sorry/index"
const CheckSNIGoogleDl = "dl.google.com"
const CheckSNIGoogle = "ipv4.google.com"

const timeout = 7000

func checkHijack(p interfaces.Vendor, network interfaces.RequestOptionsNetwork) (speedIP string, realIP string) {
	speedIPBytes, _, _ := vendors.RequestWithRetry(p, 3, timeout, &interfaces.RequestOptions{
		URL: CheckUrlGoogle,
		SNI: CheckSNIGoogleDl,
	})
	realIPBytes, _, _ := vendors.RequestWithRetry(p, 3, timeout, &interfaces.RequestOptions{
		URL: CheckUrlGoogle,
		SNI: CheckSNIGoogle,
	})

	return extractIPAddress(speedIPBytes), extractIPAddress(realIPBytes)
}

func extractIPAddress(body []byte) string {
	re := regexp.MustCompile(`IP address:\s*([0-9a-fA-F\.:]+)<br>`)
	matches := re.FindStringSubmatch(string(body))

	if len(matches) > 1 {
		return matches[1]
	} else {
		return ""
	}
}
