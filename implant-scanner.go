package main

import (
	"flag"
	"regexp"
	"strings"

	"github.com/vulncheck-oss/go-exploit"
	"github.com/vulncheck-oss/go-exploit/c2"
	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
	"github.com/vulncheck-oss/go-exploit/random"
)

type XEImplantScanner struct{}

// control if the old scan mechanism should be used or not.
var doOldScan bool

func (sploit XEImplantScanner) ValidateTarget(conf *config.Config) bool {
	url := protocol.GenerateURL(conf.Rhost, conf.Rport, conf.SSL, "/")
	resp, body, ok := protocol.HTTPSendAndRecv("GET", url, "")
	if !ok {
		return false
	}

	server, ok := resp.Header["Server"]
	if !ok {
		output.PrintDebug("Missing Server")

		return false
	}

	if server[0] != "nginx" && server[0] != "openresty" {
		output.PrintDebug("Wrong Server")

		return false
	}

	return strings.Contains(body, "/webui")
}

func oldScanMethod(conf *config.Config) exploit.VersionCheckType {
	url := protocol.GenerateURL(conf.Rhost, conf.Rport, conf.SSL, "/webui/logoutconfirm.html?logon_hash=1")
	_, body, ok := protocol.HTTPSendAndRecv("POST", url, "")
	if !ok {
		return exploit.Unknown
	}

	re := regexp.MustCompile(`^([a-f0-9]{18})\s*$`)
	res := re.FindAllStringSubmatch(body, -1)
	if len(res) != 0 {
		output.PrintSuccess("Found", "implant-id", res[0][1], "rhost", conf.Rhost, "rport", conf.Rport, "ssl", conf.SSL)

		return exploit.Vulnerable
	}

	return exploit.NotVulnerable
}

func (sploit XEImplantScanner) CheckVersion(conf *config.Config) exploit.VersionCheckType {
	if doOldScan {
		output.PrintDebug("Scanning using old method")

		return oldScanMethod(conf)
	}

	randEndpoint := "/" + random.RandLetters(4) + "%25"
	url := protocol.GenerateURL(conf.Rhost, conf.Rport, conf.SSL, randEndpoint)
	res, body, ok := protocol.HTTPSendAndRecv("GET", url, "")
	if !ok {
		return exploit.Unknown
	}

	if res.StatusCode == 404 && strings.Contains(body, `<head><title>404 Not Found</title></head>`) {
		return exploit.Vulnerable
	}

	return exploit.NotVulnerable
}

func (sploit XEImplantScanner) RunExploit(_ *config.Config) bool {
	return true
}

func main() {
	// control if the old scan mechanism should be used or not
	flag.BoolVar(&doOldScan, "old-scan", false, "Indicates if the old scanning mechanism should be used")

	conf := config.New(config.InformationDisclosure, []c2.Impl{}, "IOS XE", "CVE-2023-20198", 80)
	sploit := XEImplantScanner{}
	exploit.RunProgram(sploit, conf)
}
