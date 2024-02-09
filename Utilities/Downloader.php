<?php

namespace CalypsDoH\Utilities;

use CalypsDoH\Utilities\UUID;

class Downloader {
    function __construct(string $identity, string $deviceName) {
        if($_GET['dl'] === 'windows') {
            self::downloadWindowsInstaller($identity, $deviceName);
        }
        self::downloadAppleProfile($identity, $deviceName);
    }

    public static function downloadAppleProfile(string $identity, string $deviceName) {
        header('Content-Type: application/x-apple-aspen-config');
        header('Content-Disposition: attachment; filename="barker-apple-'
                                    .$deviceName.'.mobileconfig"'); 
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');

        flush(); 
        echo '<?xml version="1.0" encoding="UTF-8"?>
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
                        <string>https://' . $_SERVER['HTTP_HOST'] . '/' . $identity . '/' . rawurlencode($deviceName) . '</string>
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
                    <string>' . UUID::v4() . '</string>
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
            <string>' . UUID::v4() . '</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            </dict>
            </plist>';
        die();
    }

    public static function downloadWindowsInstaller(string $identity, string $deviceName) {
        header('Content-Type: application/bat');
        header('Content-Disposition: attachment; filename="barker-windows-'
                                    .$deviceName.'.bat"'); 
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');

        flush(); 

        echo '@echo off
SET scriptpath=%~dp0
call :isAdmin

if %errorlevel% == 0 (
    goto :run
) else (
    echo Requesting administrative privileges...
    goto :UACPrompt
)

exit /b

:isAdmin
    fsutil dirty query %systemdrive% >nul
exit /b

:run
    set DoHClientAddress=https://' . $_SERVER['HTTP_HOST'] . '/' . $identity . '/' . rawurlencode($deviceName) . '
    
    curl.exe --output C:\nssm.exe --url https://barker.wemiller.com/CalypsDoH/Installers/Windows/nssm.exe
    curl.exe --output C:\dnsproxy.exe --url https://barker.wemiller.com/CalypsDoH/Installers/Windows/dnsproxy.exe
    net stop Barker
    C:\nssm.exe remove Barker
    C:\nssm.exe install Barker "C:\dnsproxy.exe" "-l 0.0.0.0 -p 53 -u %DoHClientAddress% -b 1.1.1.1:53"
    net start Barker

    rem The following for loops get a given interface\'s InterfaceIndex and GUID. We use the InterfaceIndex to set DNS, and the GUID to set DoH in the registry.
    rem We only care about network interfaces that have a GUID.
    for /f %%X in (\'wmic nic where "GUID!=NULL" Get InterfaceIndex /value\') do (
        rem We have to use a second for loop to remove the extra carrige returns from wmic output.
        rem InterfaceIndex is stored at %%I.
        for /f "tokens=1* delims==" %%H in ("%%X") do (
            for /f %%X in (\'wmic nic where "InterfaceIndex=%%I" Get GUID /value\') do (
                rem GUID is stored at %%G.
                for /f "tokens=1* delims==" %%F in ("%%X") do (
                    rem Clears existing DNS servers.
                    netsh interface ipv4 set dnsservers %%I dhcp 1>NUL
                    netsh interface ipv6 set dnsservers %%I dhcp 1>NUL
                    rem Use Local Service for DNS Server
                    netsh interface ipv4 set dnsservers %%I static 127.0.0.1 primary no 1>NUL
                    netsh interface ipv6 set dnsservers %%I static :: primary no 1>NUL
                )
            )
        )
    )

    ipconfig /flushdns 1>NUL
exit /b

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %~1", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B`';
        die();
    }
}