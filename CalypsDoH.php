<?php

namespace CalypsDoH;

include __DIR__.'/Utilities/index.php';

use CalypsDoH\Utilities\DNSLib;
use CalypsDoH\Utilities\Downloader;
use CalypsDoH\Utilities\GrepLR;
use CalypsDoH\Utilities\Logger;

class Server {
    const DOMAIN_CODE_ALLOWED = 0;
    const DOMAIN_CODE_ALLOWED_DOMAIN = 1;
    const DOMAIN_CODE_ANNOYANCE_BLOCK = 2;
    const DOMAIN_CODE_BLOCKED_DOMAIN = 3;
    const DOMAIN_CODE_ALARMING_BLOCK = 4;

    const DOH_SERVERS = [
        'https://dns.google/dns-query',
        'https://cloudflare-dns.com/dns-query',
        'https://unfiltered.adguard-dns.com/dns-query',
        'https://freedns.controld.com/p0',
    ]; 

    const ANNOYANCES = [
        "https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt",
    ];

    const ALARMABLES = [
        "https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt",
        "https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt",
    ];
 
    private bool $enableStats;
    private string $requestingAccountId = "";
    private string $requestingDeviceName = "";
    private array $allowedDomains = [];
    private array $blockedDomains = [];
    private array $alarming = [];
    private array $annoying = [];

    private string $dns = "";
    private DNSLib\Message|null $message = null;
    private string $requestedDomain = "";

    function __construct(
        array $allowedIdentities, 
        string $passphrase,
        array $dohServers = null, 
        array $alarming = null, 
        array $annoying = null, 
        array $allowedDomains = [], 
        array $blockedDomains = [], 
        int $alarmLevel = 3,
        int $blockLevel = 2,
        bool $enableStats = true,
    ) {
        $path = explode("?", $_SERVER['REQUEST_URI'])[0];
        $this->requestingIdentity = basename(dirname($path));
        $this->requestingDeviceName = basename($path);
        
        if (!in_array($this->requestingIdentity, $allowedIdentities)) {
            die('Invalid Identifier passed to request');
        }

        if (isset($_GET['dl'])) {
            new Downloader($this->requestingIdentity, $this->requestingDeviceName);
        }

        $this->dns = ($_GET['dns'] ?? base64_encode(file_get_contents('php://input')));
        
        try {
            $this->message = (new DNSLib\Parser())->parseMessage(base64_decode($this->dns));
        } catch(\InvalidArgumentException $e){
            $this->getAllowedResponse($dohServers ?? self::DOH_SERVERS, $this->dns);
            die();
        }

        $this->enableStats = $enableStats;
        $this->requestedDomain = $this->message->questions[0]->name;
        $this->allowedDomains = $allowedDomains;
        $this->blockedDomains = $blockedDomains;
        $this->alarming = $alarming ?? self::ALARMABLES;
        $this->annoying = $annoying ?? self::ANNOYANCES;

        $domainLevel = $this->checkBlocks();
        if ($domainLevel >= $alarmLevel) {
            $this->generateBlockedResponse($this->message);
            $this->updateLogs($passphrase, true, false);
        } else if ($domainLevel >= $blockLevel) {
            $this->generateBlockedResponse($this->message);
            $this->updateLogs($passphrase, false, false);
        }

        $this->getAllowedResponse($dohServers ?? self::DOH_SERVERS, $this->dns);
        $this->updateLogs($passphrase, false, true);
    }

    private function updateLogs(string $passphrase, bool $alarmable = false, bool $allowed = true) {
        $stats = Logger::getLogs($passphrase, $this->requestingIdentity, 'stats');
        $times = Logger::getLogs($passphrase, $this->requestingIdentity, 'times');
        $requests = Logger::getLogs($passphrase, $this->requestingIdentity, 'requests');

        $statsLogs = $stats['data'];
        $timesLogs = $times['data'];
        $requestsLogs = $requests['data'];

        if (
            $statsLogs === false
            || $timesLogs === false
            || $requestsLogs === false
        ) {
            return;
        }

        if ($alarmable === true && $allowed === false) {
            $time = date('Y-m-d H:i:s');
            if($this->enableStats) {
                $statsLogs["alarmed"]++;
            }
            $requestsLogs[$this->requestedDomain] = "Denied Access to Website: {$this->requestedDomain} On Device: {$this->requestingDeviceName} At: {$time}";
        }

        if ($this->enableStats && $allowed === false && $alarmable === false) {
            $statsLogs["annoyance"]++;
        }

        if ($this->enableStats && $allowed === true) {
            $statsLogs["allowed"]++;
        } 

        if ($this->enableStats) {
            $statsLogs["requests"]++;
            $timesLogs["inactivity"] = time();
        }
        Logger::saveLogs($passphrase, 'stats', $statsLogs, $stats['handler']);
        Logger::saveLogs($passphrase, 'times', $timesLogs, $times['handler']);
        Logger::saveLogs($passphrase,'requests', $requestsLogs, $requests['handler']);
    }

    private function getAllowedResponse($dnsServers, $dns) {
        $dnsServer = $dnsServers[
            random_int(
                0,
                count($dnsServers) - 1
            )
        ];

        $opts = [
            'http' => [
                'method' => 'GET',
                'header' => 'Accept: '.$_SERVER['HTTP_ACCEPT']
            ]
        ];

        $context = stream_context_create($opts);
        $dohResponse = file_get_contents($dnsServer . '?dns='.urlencode(rtrim($dns, "=")), false, $context);
        
        if (empty($dohResponse)) {
            error_log("Unsupported DoH Server: {$dnsServer}");
        }

        $this->closeClientConnectionWithPayload($dohResponse);
    }

    private function generateBlockedResponse($message = null) {
        if (is_null($message)) {
            $message = new CalypsDoH\Utilities\DNSLib\Message();
        }

        $message->qr = true;
        $message->rd = true;
        $message->id = DNSLib\Message::generateId();
        $message->rcode = DNSLib\Message::RCODE_NAME_ERROR;
        $this->closeClientConnectionWithPayload((new DNSLib\BinaryDumper())->toBinary($message));
    }

    private function closeClientConnectionWithPayload(string $payload) {
        ob_start();
        echo $payload;
        $size = ob_get_length();
        header('Content-Type: '.$_SERVER['HTTP_ACCEPT']);
        header("Content-Encoding: none");
        header("Content-Length: {$size}");
        header("Connection: close");
        ob_end_flush();
        @ob_flush();
        flush();
        if(session_id()) session_write_close();
    }

    private function checkBlocks() : int {
        foreach ($this->allowedDomains as $allowedDomainFragment) {
            if (strstr($this->requestedDomain, $allowedDomainFragment) !== false) {
                return self::DOMAIN_CODE_ALLOWED_DOMAIN;
            }
        } 
    
        foreach ($this->blockedDomains as $blockedDomainFragment){
            if (strstr($this->requestedDomain, $blockedDomainFragment) !== false) {
                return self::DOMAIN_CODE_BLOCKED_DOMAIN;
            }
        }
        
        if ($this->isAlarming($this->requestedDomain)) {
            return self::DOMAIN_CODE_ALARMING_BLOCK;
        }

        if ($this->isAnnoying($this->requestedDomain)) {
            return self::DOMAIN_CODE_ANNOYANCE_BLOCK;
        }

        return self::DOMAIN_CODE_ALLOWED;
    }

    private function isAlarming($domain) {
        $directory = __DIR__.DIRECTORY_SEPARATOR."Storage".DIRECTORY_SEPARATOR."ALARMING".DIRECTORY_SEPARATOR;
        if (!file_exists($directory)) {
            mkdir($directory, 0777, true);
        }

        foreach ($this->alarming as $blocklist) {
            $localPath = $directory.basename($blocklist);
            if (!is_file($localPath) || time() - filemtime($localPath) >= 60 * 60 * 24 * 1) {
                file_put_contents($localPath, file_get_contents($blocklist));
            }

            if (GrepLR::run($localPath, $domain)) {
                return true;
            }
        }

        return false;
    }
    
    private function isAnnoying($domain) {
        $directory = __DIR__.DIRECTORY_SEPARATOR."Storage".DIRECTORY_SEPARATOR."ANNOYANCES".DIRECTORY_SEPARATOR;
        if (!file_exists($directory)) {
            mkdir($directory, 0777, true);
        }

        foreach ($this->annoying as $blocklist) {
            $localPath = $directory.basename($blocklist);
            if (!is_file($localPath) || time() - filemtime($localPath) >= 60 * 60 * 24 * 1) {
                file_put_contents($localPath, file_get_contents($blocklist));
            }

            if (GrepLR::run($localPath, $domain)) {
                return true;
            }
        }

        return false;
    }
} 
