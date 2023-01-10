<?php

include __DIR__.'/CalypsDoH.php';

new CalypsDoH\Server(
    allowedIdentities: [
        /**
         * These can be UUIDs or whatever url safe string you want to use to associate an allowed user with their logs
         */
    ],
    passphrase: getenv('ENCRYPTION_PASSPHRASE_FOR_LOGS'),
    dohServers: null, // Optional array of DoH Server endpoints that support GET DoH Queries via the ?dbs=... param.
    alarming: null, // Optional URLs of blocklists that have a domain per line that you want the requests logged to an encrypted file.
    annoying: null, // Optional URLs of blocklists that have a domain per line that you want blocked silently.
    allowedDomains: [], // Optional array of any portion of a domain that you want to always allow.
    blockedDomains: [], // Optional array of any portion of a domain that you want to always block.
    blockLevel: 3, // The DOMAIN_CODE level that requests should be blocked. See CalypsDoH.php Constants
    enableStats: true, // Optional boolean to disable request stats from being logged.
);
