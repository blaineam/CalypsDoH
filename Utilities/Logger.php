<?php

namespace CalypsDoH\Utilities;

use CalypsDoH\Utilities\AES;

class Logger {
    const TEMPLATES = [
        "stats" => [
            "requests" => 0,
            "allowed" => 0,
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
        return __DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."Storage".DIRECTORY_SEPARATOR.$identity."-".$type.".json";
    }

    public static function getLogs(string $passphrase, string $identity, string $type): array {
        $logPath = self::getLogPath($identity, $type);
        $handler = fopen($logPath, "c+");

        if (!flock($handler, LOCK_EX)) {
            fclose($handler);
            return ['handler' => $handler, 'data' => false];
        }

        if(file_exists($logPath)) {
            $data = "";
            while (!feof($handler)) { $data .= fread($handler, 1024); }
            $data = trim($data);
            if (empty($data)) {
                $logs = self::TEMPLATES[$type];
            } else if(($logs = AES::Decrypt($data, $passphrase)) || json_last_error() === JSON_ERROR_NONE) {
                return ['handler' => $handler, 'data' => $logs];
            } else {
                error_log("could not read logs file: {$logPath}");
                return ['handler' => $handler, 'data' => false];
            }
        } else {
            $logs = self::TEMPLATES[$type];
        }

        return ['handler' => $handler, 'data' => $logs];
    }

    public static function saveLogs(string $passphrase, string $type, array $logs, $handler) {
        if (
            in_array($type, ['stats', 'times']) 
            && count(array_intersect_key(array_flip(array_keys(self::TEMPLATES[$type])), $logs)) !== count(self::TEMPLATES[$type])
        ) {
            error_log('Invalid structure for attempted log save.');
            return;
        }
        
        ftruncate($handler,0);
        fwrite($handler, AES::Encrypt($logs, $passphrase));
        flock($handler, LOCK_UN);
        fclose($handler);
    }

}