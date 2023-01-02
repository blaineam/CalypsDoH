<?php

namespace CalypsDoH\Utilities;

use AES;

class Logger {
    const TEMPLATES = [
        "stats" => [
            "requests" => 0,
            "normal" => 0,
            "allowed" => 0,
            "blocked" => 0,
            "annoyance" => 0,
            "alarmed" => 0,
        ],
        "times" => [
            "alarms" => 0,
            "reports" => 0,
            "inactivity" => 0,
        ],
        "requests" => [
            
        ],
    ];

    private static function getLogPath(string $identity, string $type): string {
        return __DIR__.DIRECTORY_SEPARATOR."Storage".DIRECTORY_SEPARATOR.$identity."-".$type.".json";
    }

    public static function getLogs(string $passphrase, string $identity, string $type): array {
        $logPath = self::getLogPath($identity, $type);
        if(file_exists($logPath)) {
            if($logs = AES::Decrypt(file_get_contents($logPath), $passphrase)) {
                return $logs;
            } else {
                error_log("could not read logs file: {$logPath}");
                return false;
            }
        } else {
            $logs = self::TEMPLATES[$type];
        }

        return $logs;
    }

    public static function saveLogs(string $passphrase, string $identity, string $type, array $logs) {
        if (
            in_array($type, ['stats', 'times']) 
            && count(array_intersect_key(array_flip(array_keys(self::TEMPLATES[$type])), $logs)) !== count(self::TEMPLATES[$type])
        ) {
            error_log('Invalid structure for attempted log save.');
            return;
        }

        $logPath = self::getLogPath($identity, $type);
        file_put_contents($logPath, AES::Encrypt($logs, $passphrase));
    }

}