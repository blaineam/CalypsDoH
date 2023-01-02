<?php

namespace CalypsDoH\Utilities;

class GrepLR {
    function __constuct(string $filename, string $needle): bool {
        $handle = fopen($filename, "r");
        if ($handle) {
            while (($line = fgets($handle)) !== false) {
                if($line === $needle) {
                    return true;
                }
            }

            fclose($handle);
        }
        return false;
    }
}