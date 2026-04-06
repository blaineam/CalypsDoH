package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var safeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9_\-]`)
var safeHostRe = regexp.MustCompile(`[^a-zA-Z0-9.\-:]`)

func sanitizeHost(host string) string {
	return safeHostRe.ReplaceAllString(host, "")
}

func sanitizeFilename(name string) string {
	return safeFilenameRe.ReplaceAllString(name, "_")
}

func parseIP4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv4zero
	}
	return ip.To4()
}

func parseIP6(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv6zero
	}
	return ip
}

func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

func GenerateAppleProfile(w http.ResponseWriter, host, identity, deviceName, safeName string, cfg *Config) {
	serverURL := fmt.Sprintf("https://%s%s%s%s%s",
		xmlEscape(host),
		xmlEscape(cfg.DLPrefix),
		xmlEscape(identity),
		xmlEscape(cfg.DLDelimiter),
		url.PathEscape(deviceName),
	)

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="barker-apple-%s.mobileconfig"`, safeName))
	w.Header().Set("Cache-Control", "must-revalidate")

	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
    <dict>
        <key>DNSSettings</key>
        <dict>
            <key>DNSProtocol</key>
            <string>HTTPS</string>
            <key>ServerURL</key>
            <string>%s</string>
        </dict>
        <key>PayloadDescription</key>
        <string>Configures device to use Barker Encrypted DNS over HTTPS</string>
        <key>PayloadDisplayName</key>
        <string>Barker DNS over HTTPS</string>
        <key>PayloadIdentifier</key>
        <string>com.apple.dnsSettings.managed.e17cf1fa-0f0f-48a9-a68b-395804ed1850</string>
        <key>PayloadType</key>
        <string>com.apple.dnsSettings.managed</string>
        <key>PayloadUUID</key>
        <string>%s</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>ProhibitDisablement</key>
        <false/>
    </dict>
</array>
<key>PayloadDescription</key>
<string>Adds the Barker DNS to Big Sur and iOS 14 based systems</string>
<key>PayloadDisplayName</key>
<string>Barker DNS over HTTPS</string>
<key>PayloadIdentifier</key>
<string>com.barker.apple-dns</string>
<key>PayloadRemovalDisallowed</key>
<false/>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadUUID</key>
<string>%s</string>
<key>PayloadVersion</key>
<integer>1</integer>
</dict>
</plist>`, serverURL, uuid.New().String(), uuid.New().String())
}

func GenerateWindowsInstaller(w http.ResponseWriter, host, identity, deviceName, safeName string, cfg *Config) {
	dohAddr := fmt.Sprintf("https://%s%s%s%s%s",
		host,
		cfg.DLPrefix,
		url.PathEscape(identity),
		cfg.DLDelimiter,
		url.PathEscape(deviceName),
	)

	w.Header().Set("Content-Type", "application/bat")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="barker-windows-%s.bat"`, safeName))
	w.Header().Set("Cache-Control", "must-revalidate")

	fmt.Fprintf(w, `@echo off
SET scriptpath=%%~dp0
call :isAdmin

if %%errorlevel%% == 0 (
    goto :run
) else (
    echo Requesting administrative privileges...
    goto :UACPrompt
)

exit /b

:isAdmin
    fsutil dirty query %%systemdrive%% >nul
exit /b

:run
    set DoHClientAddress=%s

    curl.exe --output C:\nssm.exe --url https://barker.wemiller.com/CalypsDoH/Installers/Windows/nssm.exe
    curl.exe --output C:\dnsproxy.exe --url https://barker.wemiller.com/CalypsDoH/Installers/Windows/dnsproxy.exe
    net stop Barker
    C:\nssm.exe remove Barker
    C:\nssm.exe install Barker "C:\dnsproxy.exe" "-l 0.0.0.0 -p 53 -u %%DoHClientAddress%% -b 1.1.1.1:53"
    net start Barker

    rem The following for loops get a given interface's InterfaceIndex and GUID. We use the InterfaceIndex to set DNS, and the GUID to set DoH in the registry.
    rem We only care about network interfaces that have a GUID.
    for /f %%%%X in ('wmic nic where "GUID!=NULL" Get InterfaceIndex /value') do (
        rem We have to use a second for loop to remove the extra carrige returns from wmic output.
        rem InterfaceIndex is stored at %%%%I.
        for /f "tokens=1* delims==" %%%%H in ("%%%%X") do (
            for /f %%%%X in ('wmic nic where "InterfaceIndex=%%%%I" Get GUID /value') do (
                rem GUID is stored at %%%%G.
                for /f "tokens=1* delims==" %%%%F in ("%%%%X") do (
                    rem Clears existing DNS servers.
                    netsh interface ipv4 set dnsservers %%%%I dhcp 1>NUL
                    netsh interface ipv6 set dnsservers %%%%I dhcp 1>NUL
                    rem Use Local Service for DNS Server
                    netsh interface ipv4 set dnsservers %%%%I static 127.0.0.1 primary no 1>NUL
                    netsh interface ipv6 set dnsservers %%%%I static :: primary no 1>NUL
                )
            )
        )
    )

    ipconfig /flushdns 1>NUL
exit /b

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%%temp%%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c %%~s0 %%~1", "", "runas", 1 >> "%%temp%%\getadmin.vbs"

    "%%temp%%\getadmin.vbs"
    del "%%temp%%\getadmin.vbs"
    exit /B`, dohAddr)
}
