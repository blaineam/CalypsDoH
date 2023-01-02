<?php

namespace CalypsDoH\Utilities;

class UUID {
    function __constuct() {
        $out = bin2hex(random_bytes(18));
        $out[8]  = "-";
        $out[13] = "-";
        $out[18] = "-";
        $out[23] = "-";
        $out[14] = "4";
        $out[19] = ["8", "9", "a", "b"][random_int(0, 3)];
        return $out;
    }
}