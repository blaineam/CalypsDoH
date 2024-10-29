<?php

namespace CalypsDoH\Utilities;

class GrepLR
{
    public static function run(string $filename, string $needle): bool
    {
        $handle = fopen($filename, 'r');
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                if ($line === $needle) {
                    return true;
                }
            }

            fclose($handle);
        }
        return false;
    }
}
