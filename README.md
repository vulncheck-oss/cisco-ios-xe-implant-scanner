# Cisco IOS XE Implant Scanner

Scans for the IOS XE implant as described by [Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z) and [Cisco Talos](https://blog.talosintelligence.com/active-exploitation-of-cisco-ios-xe-software/). The scanner will send an HTTP POST request to `/webui/logoutconfirm.html?logon_hash=1` and look for the 18 byte hexstring in response. The scanner output will have a line like this when it finds an implant:

```sh
time=2023-10-17T06:09:02.967-04:00 level=SUCCESS msg=Found implant-id=1a80b7389ccd0a5dab rhost=192.168.1.1 rport=80 ssl=false
```

When no implant is found, the scanner will say something like:

```
{"time":"2023-10-17T06:13:48.241233896-04:00","level":"ERROR","msg":"The target appears to be a patched version.","host":"192.168.1.1","port":80}
```

Note that this isn't indicative of a patched version, only that an implant wasn't found. This is just generic output from [go-exploit](https://github.com/vulncheck-oss/go-exploit)'s version scanner. Because this is built on go-exploit, it supports a variety of scanning functionality. Sample usage follows:

## Scanning One Host

```sh
$ ./build/implant-scanner -rhost 192.168.1.1 -rport 80 -proxy socks5://127.0.0.1:9050 -a -v -c
time=2023-10-17T06:08:59.586-04:00 level=STATUS msg="Starting target" index=0 host=192.168.1.1port=80 ssl=false "ssl auto"=true
time=2023-10-17T06:09:00.882-04:00 level=STATUS msg="Validating IOS XE target" host=192.168.1.1port=80
time=2023-10-17T06:09:02.237-04:00 level=SUCCESS msg="Target validation succeeded!" host=192.168.1.1port=80
time=2023-10-17T06:09:02.237-04:00 level=STATUS msg="Running a version check on the remote target" host=192.168.1.1port=80
time=2023-10-17T06:09:02.967-04:00 level=SUCCESS msg=Found implant-id=1a80b7389ccd0a5dab rhost=192.168.1.1rport=80 ssl=false
time=2023-10-17T06:09:02.967-04:00 level=SUCCESS msg="The target appears to be a vulnerable version!" host=192.168.1.1port=80
```

## Scanning One Host Through a Proxy

```sh
$ ./build/implant-scanner -rhost 192.168.1.1-rport 80 -proxy socks5://127.0.0.1:9050 -a -v -c
time=2023-10-17T06:08:59.586-04:00 level=STATUS msg="Starting target" index=0 host=192.168.1.1port=80 ssl=false "ssl auto"=true
time=2023-10-17T06:09:00.882-04:00 level=STATUS msg="Validating IOS XE target" host=192.168.1.1port=80
time=2023-10-17T06:09:02.237-04:00 level=SUCCESS msg="Target validation succeeded!" host=192.168.1.1port=80
time=2023-10-17T06:09:02.237-04:00 level=STATUS msg="Running a version check on the remote target" host=192.168.1.1port=80
time=2023-10-17T06:09:02.967-04:00 level=SUCCESS msg=Found implant-id=1a80b7389ccd0a5dab rhost=192.168.1.1rport=80 ssl=false
time=2023-10-17T06:09:02.967-04:00 level=SUCCESS msg="The target appears to be a vulnerable version!" host=192.168.1.1port=80
```

## Scanning a File of Hosts and Logging JSON to File

See go-exploit [documentation](https://github.com/vulncheck-oss/go-exploit/blob/main/docs/scanning.md) for a better understanding of the -rhosts-file format.

```sh
$ ./build/implant-scanner -rhosts-file targets -log-json -log-file ./logs/output.json -v -c
$ tail logs/output.json
{"time":"2023-10-17T06:16:07.24555914-04:00","level":"STATUS","msg":"Validating IOS XE Implant target","host":"192.168.1.1","port":443}
{"time":"2023-10-17T06:16:10.363281285-04:00","level":"SUCCESS","msg":"Target validation succeeded!","host":"192.168.1.1","port":443}
{"time":"2023-10-17T06:16:10.363345035-04:00","level":"STATUS","msg":"Running a version check on the remote target","host":"192.168.1.1","port":443}
```