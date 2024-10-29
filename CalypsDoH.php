<?php

namespace CalypsDoH;

include __DIR__ . '/Utilities/index.php';

use CalypsDoH\Utilities\DNSLib;
use CalypsDoH\Utilities\Downloader;
use CalypsDoH\Utilities\GrepLR;
use CalypsDoH\Utilities\Logger;

class Server
{
    const DOMAIN_CODE_ALLOWED = 0;
    const DOMAIN_CODE_ALLOWED_DOMAIN = 1;
    const DOMAIN_CODE_ANNOYANCE_BLOCK = 2;
    const DOMAIN_CODE_BLOCKED_DOMAIN = 3;
    const DOMAIN_CODE_ALARMING_BLOCK = 4;

    const DOH_SERVERS = [
        'https://dns.google/dns-query',
        'https://cloudflare-dns.com/dns-query',
    ];

    const ANNOYANCES = [
        'https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/fraud-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/piracy-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/torrent-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt',
    ];

    const ALARMABLES = [
        'https://blocklistproject.github.io/Lists/alt-version/porn-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/drugs-nl.txt',
        'https://blocklistproject.github.io/Lists/alt-version/gambling-nl.txt',
    ];

    private bool $enableStats;
    private string $requestingIdentity = '';
    private string $requestingDeviceName = '';
    private array $allowedDomains = [];
    private array $blockedDomains = [];
    private array $alarming = [];
    private array $annoying = [];

    private string $dns = '';
    private DNSLib\Message|null $message = null;
    private string $requestedDomain = '';

    public function __construct(
        array $allowedIdentities = null,
        string $passphrase,
        array $dohServers = null,
        array $alarming = null,
        array $annoying = null,
        array $allowedDomains = [],
        array $remaps = [],
        array $blockedDomains = [],
        string $requestingIdentity = null,
        string $requestingDeviceName = null,
        int $blockLevel = 2,
        bool $enableStats = true,
    ) {
        set_time_limit(1);
        if (is_null($requestingDeviceName) || is_null($requestingIdentity)) {
            $path = explode('?', $_SERVER['REQUEST_URI'])[0];
            $this->requestingIdentity = basename(dirname($path));
            $this->requestingDeviceName = basename($path);
        } else {
            $this->requestingIdentity = $requestingIdentity;
            $this->requestingDeviceName = $requestingDeviceName;
        }

        if (!is_null($allowedIdentities) && !in_array($this->requestingIdentity, $allowedIdentities)) {
            die('Invalid Identifier passed to request');
        }

        if (isset($_GET['dl'])) {
            new Downloader($this->requestingIdentity, $this->requestingDeviceName);
        }

        $this->dns = ($_GET['dns'] ?? base64_encode(file_get_contents('php://input')));
        try {
            $this->message = (new DNSLib\Parser())->parseMessage(base64_decode($this->dns));
        } catch (\InvalidArgumentException $e) {
            $this->getAllowedResponse($dohServers ?? self::DOH_SERVERS, $this->dns);
            return;
        }

        $this->enableStats = $enableStats;
        $this->requestedDomain = strtolower($this->message->questions[0]->name);
        $this->allowedDomains = array_filter($allowedDomains);
        $this->blockedDomains = array_filter($blockedDomains);
        $this->alarming = $alarming ?? self::ALARMABLES;
        $this->annoying = $annoying ?? self::ANNOYANCES;

        if (in_array($this->requestedDomain, [
            'mask.icloud.com',
            'mask-h2.icloud.com'
        ])) {
            $this->generateBlockedResponse($this->message);
            return;
        }

        foreach ($remaps as $domainIpPair) {
            if ($domainIpPair[0] === $this->requestedDomain) {
                $this->generateRemappedResponse($this->message, $domainIpPair[1]);
            }
        }

        $domainLevel = $this->checkBlocks();
        if ($domainLevel >= $blockLevel) {
            $this->generateBlockedResponse($this->message);
        } else {
            $this->getAllowedResponse($dohServers ?? self::DOH_SERVERS, $this->dns);
        }

        if ($this->enableStats) {
            Logger::appendLogs($passphrase, $this->requestingIdentity, $this->requestingDeviceName, $this->requestedDomain, $domainLevel);
        }
    }

    private function getAllowedResponse($dnsServers, $dns)
    {
        $dnsServer = $dnsServers[
            random_int(
                0,
                count($dnsServers) - 1
            )
        ];
        $this->closeConnection(
            file_get_contents(
                $dnsServer . '?dns=' . urlencode(rtrim($dns, '=')),
                false,
                stream_context_create(
                    [
                        'http' => [
                            'method' => 'GET',
                            'header' => 'Accept: application/dns-message',
                        ]
                    ]
                )
            )
        );
    }

    private function generateBlockedResponse($message = null)
    {
        if (is_null($message)) {
            $message = new Utilities\DNSLib\Message();
            $message->qr = true;
            $message->rd = true;
            $message->id = DNSLib\Message::generateId();
            $message->rcode = DNSLib\Message::RCODE_NAME_ERROR;
        } else {
            $message->qr = true;
            $message->rd = true;
            $message->rcode = DNSLib\Message::RCODE_NAME_ERROR;
        }

        $binary = (new DNSLib\BinaryDumper())->toBinary($message);
        $this->closeConnection($binary);
    }

    private function generateRemappedResponse($message, $ip)
    {
        $message->rcode = DNSLib\Message::RCODE_OK;
        $message->qr = true;
        $message->rd = true;
        $message->answers[] = new DNSLib\Record(
            $this->requestedDomain,
            DNSLib\Message::TYPE_A,
            DNSLib\Message::CLASS_IN,
            0,
            $ip
        );
        $binary = (new DNSLib\BinaryDumper())->toBinary($message);
        $this->closeConnection($binary);
    }

    public function closeConnection($body)
    {
        set_time_limit(0);
        ignore_user_abort(true);
        ob_start();
        echo $body;
        header("Connection: close\r\n");
        ob_end_flush();
    }

    private function checkBlocks(): int
    {
        foreach ($this->allowedDomains as $allowedDomainFragment) {
            if (strstr($this->requestedDomain, $allowedDomainFragment) !== false) {
                return self::DOMAIN_CODE_ALLOWED_DOMAIN;
            }
        }

        foreach ($this->blockedDomains as $blockedDomainFragment) {
            if (strstr($this->requestedDomain, $blockedDomainFragment) !== false) {
                return self::DOMAIN_CODE_BLOCKED_DOMAIN;
            }
        }

        $useExec = @exec('echo EXEC') === 'EXEC';

        if ($this->isAlarming($this->requestedDomain, $useExec)) {
            return self::DOMAIN_CODE_ALARMING_BLOCK;
        }

        if ($this->isAnnoying($this->requestedDomain, $useExec)) {
            return self::DOMAIN_CODE_ANNOYANCE_BLOCK;
        }

        return self::DOMAIN_CODE_ALLOWED;
    }

    private function isAlarming($domain, bool $useExec = true)
    {
        $directory = __DIR__ . DIRECTORY_SEPARATOR . 'Storage' . DIRECTORY_SEPARATOR . 'ALARMING' . DIRECTORY_SEPARATOR;
        if (!file_exists($directory)) {
            mkdir($directory, 0777, true);
        }

        foreach ($this->alarming as $blocklist) {
            $localPath = $directory . basename($blocklist);
            if (!is_file($localPath) || time() - filemtime($localPath) >= 60 * 60 * 24 * 1) {
                file_put_contents($localPath, file_get_contents($blocklist));
            }

            if (!$useExec) {
                if (GrepLR::run($localPath, $domain)) {
                    return true;
                }
            }
        }

        if ($useExec) {
            $ouput = [];
            exec("grep -q -Fx '" . escapeshellarg($domain) . "' {$directory}*", $ouput, $exitCode);
            return $exitCode == 0;
        }

        return false;
    }

    private function isAnnoying($domain, bool $useExec = true)
    {
        $directory = __DIR__ . DIRECTORY_SEPARATOR . 'Storage' . DIRECTORY_SEPARATOR . 'ANNOYANCES' . DIRECTORY_SEPARATOR;
        if (!file_exists($directory)) {
            mkdir($directory, 0777, true);
        }

        foreach ($this->annoying as $blocklist) {
            $localPath = $directory . basename($blocklist);
            if (!is_file($localPath) || time() - filemtime($localPath) >= 60 * 60 * 24 * 1) {
                file_put_contents($localPath, file_get_contents($blocklist));
            }

            if (!$useExec) {
                if (GrepLR::run($localPath, $domain)) {
                    return true;
                }
            }
        }

        if ($useExec) {
            $ouput = [];
            exec("grep -q -Fx '" . escapeshellarg($domain) . "' {$directory}*", $ouput, $exitCode);
            return $exitCode == 0;
        }

        return false;
    }
}
