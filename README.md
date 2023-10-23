# Cisco IOS XE Implant Scanner

On October 23, 2023, with all implants no longer responding to requests to `/webui/logoutconfirm.html`, [Fox-IT](https://github.com/fox-it/cisco-ios-xe-implant-detection) developed a new way to determine if a system is compromised or not. In particular, instead of responding to requests with a redirect to the login, the attacker's implant had logic to return 404 if requested URI contained `%`. So this scanner now sends an HTTP get request like `/Fadf%25`. A system with an implant will return the following payload:

```
<html>
<head><title>404 Not Found</title></head>
<body bgcolor="white">
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
```

Usage is the same as before (see "Old Docs" section for more usage info) but we can no longer recover the implant-id.

## Example output for an implanted host

```
./build/implant-scanner -a -v -c -rhost 10.9.49.180
time=2023-10-23T14:33:07.581-04:00 level=STATUS msg="Starting target" index=0 host=10.9.49.180 port=80 ssl=false "ssl auto"=true
time=2023-10-23T14:33:08.782-04:00 level=STATUS msg="Validating IOS XE target" host=10.9.49.180 port=80
time=2023-10-23T14:33:10.115-04:00 level=SUCCESS msg="Target validation succeeded!" host=10.9.49.180 port=80
time=2023-10-23T14:33:10.115-04:00 level=STATUS msg="Running a version check on the remote target" host=10.9.49.180 port=80
time=2023-10-23T14:33:10.624-04:00 level=SUCCESS msg="The target appears to be a vulnerable version!" host=10.9.49.180 port=80
```

## Example output for a host with no implant

```
./build/implant-scanner -a -v -c -rhost 10.9.49.124
time=2023-10-23T14:34:31.207-04:00 level=STATUS msg="Starting target" index=0 host=10.9.49.124 port=80 ssl=false "ssl auto"=true
time=2023-10-23T14:34:31.340-04:00 level=STATUS msg="Validating IOS XE target" host=10.9.49.124 port=80
time=2023-10-23T14:34:31.363-04:00 level=SUCCESS msg="Target validation succeeded!" host=10.9.49.124 port=80
time=2023-10-23T14:34:31.363-04:00 level=STATUS msg="Running a version check on the remote target" host=10.9.49.124 port=80
time=2023-10-23T14:34:31.378-04:00 level=ERROR msg="The target appears to be a patched version." host=10.9.49.124 port=80
```

# Old Docs

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
