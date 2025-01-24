<?php

namespace CalypsDoH\Utilities;

use CalypsDoH\Server;

class Category
{

    public static function determine(
        string $domain,
        bool $useExec = true,
        string|null $webShrinkerApiKey = null,
        string|null $webShrinkerApiSecret = null,
    ): string {
        $storageDirectory = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'Storage' . DIRECTORY_SEPARATOR;
        $cachePath = $storageDirectory . 'categories.json';
        if (file_exists($cachePath)) {
            $cachedCategories = json_decode(file_get_contents($cachePath) ?: '{}', true) ?: [];
            if (array_key_exists($domain, $cachedCategories)) {
                return $cachedCategories[$domain];
            }
        } else {
            $cachedCategories = [];
        }

        if (!is_null($webShrinkerApiKey) && !is_null($webShrinkerApiSecret)) {
            $options = ['key' => $webShrinkerApiKey];
            $parameters = http_build_query($options);
            $request = sprintf('categories/v3/%s?%s', base64_encode($domain), $parameters);
            $hash = md5(sprintf('%s:%s', $webShrinkerApiSecret, $request));
            $request = "https://api.webshrinker.com/{$request}&hash={$hash}";

            // Initialize cURL and use pre-signed URL authentication
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $request);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            $response = curl_exec($ch);
            $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $json = json_decode($response, true);
            switch ($status_code) {
                case 200:
                    $category = $json['data'][0]['categories'][0]['label'];
                    file_put_contents($cachePath, json_encode(array_merge($cachedCategories, [$domain => $category])));
                    return $category;
                    // Do something with the JSON response
                    break;
                case 202:
                    // The response may have categories but the system is calculating them again,
                    // check back soon
                    break;
                case 400:
                    // Bad or malformed HTTP request
                    break;
                case 401:
                    // Unauthorized
                    break;
                case 402:
                    // Request limit reached
                    break;
            }
            return 'Unknown';
        }

        $directory = $storageDirectory . 'ALARMING' . DIRECTORY_SEPARATOR;
        if (!file_exists($directory)) {
            mkdir($directory, 0777, true);
        }

        foreach (Server::ALARMABLES as $blocklist) {
            $localPath = $directory . basename($blocklist);
            if (!is_file($localPath) || time() - filemtime($localPath) >= 60 * 60 * 24 * 1) {
                file_put_contents($localPath, file_get_contents($blocklist));
            }
            $category = str_replace('-nl.txt', '', basename($localPath));

            if (!$useExec) {
                if (GrepLR::run($localPath, $domain)) {
                    return $category;
                }
            } else {
                $output = [];
                exec("grep -q -Fx '" . escapeshellarg($domain) . "' {$directory}*", $ouput, $exitCode);
                if ($exitCode == 0) {
                    return $category;
                }
            }
        }
        return 'User Defined Block List';
    }
}
