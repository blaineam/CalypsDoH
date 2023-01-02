<?php

namespace CalypsDoH\Utilities;

use CalypsDoH\Utilities\UUID;

class Downloader {
    function __construct(string $identity, string $deviceName) {
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
                        <string>https://' . $_SERVER['HTTP_REFERER'] . '/' . $identity . '/' . rawurlencode($deviceName) . '</string>
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
}