# CalypsDoH
A Simple DoH Server written in PHP with support for Blocklists and Basic Logging

## Use Case
There was a need for being able to spin up a DoH Compatible Server with the ability to capture and or block requests based on the request payload. This Project aims at providing a simple DoH Server that works with basic PHP Servers by limiting the dependencies used so it is highly portable. 

## Architecture
The overall design is quite simple:
1. Listen for the standard types of DoH requests that pass either a GET param or post a binary payload in DNS Wire Format.
2. Attempt to parse the binary payload to determine the requested domain name.
3. Check the domain name and determine a DOMAIN_CODE_LEVEL by using publicly available blocklists that are cached to the server for a period of time.
4. Optionally save logs about the request to an encrypted file for use later by other systems such as a Notifier.
5. If the domain is in a block list then respond with a NXDOMAIN DNS Response.
6. If the domain is allowed, proxy the request to a random DoH Server

## How To Setup
1. Clone the repo to a PHP server instance
2. Point a public domain name at the server.
3. Update the passphrase either by setting an ENV variable or updating index.php
4. Update the AllowedIdentities array in index.php
5. Optionally setup any other options in index.php for your desired use case.
6. To setup a DoH client using an apple device just visit your public domain using the following template:
    - `https://<public_domain_name_from_step_2>/<allowed_identity_from_step_4>/<any_device_name_for_your_client_url_encoded>?dl`
7. Enjoy :)

## Credits
This project would not have been possible without re-using some MIT Licensed code from the following repos:
[https://github.com/reactphp/dns](https://github.com/reactphp/dns)

[https://github.com/brainfoolong/cryptojs-aes-php](https://github.com/brainfoolong/cryptojs-aes-php)
