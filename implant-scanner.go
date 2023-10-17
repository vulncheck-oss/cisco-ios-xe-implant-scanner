package main

import (
	"regexp"
	"strings"

	"github.com/vulncheck-oss/go-exploit"
	"github.com/vulncheck-oss/go-exploit/c2"
	"github.com/vulncheck-oss/go-exploit/config"
	"github.com/vulncheck-oss/go-exploit/output"
	"github.com/vulncheck-oss/go-exploit/protocol"
)

type XEImplantScanner struct{}

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

	if server[0] != "nginx" {
		output.PrintDebug("Wrong Server")

		return false
	}

	return strings.Contains(body, "/webui")
}

func (sploit XEImplantScanner) CheckVersion(conf *config.Config) exploit.VersionCheckType {
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

func (sploit XEImplantScanner) RunExploit(_ *config.Config) bool {
	return true
}

func main() {
	conf := config.New(config.InformationDisclosure, []c2.Impl{}, "IOS XE", "CVE-2023-20198", 80)

	sploit := XEImplantScanner{}
	exploit.RunProgram(sploit, conf)
}
