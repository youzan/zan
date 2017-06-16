<?php

require_once __DIR__ . "/../../Bootstrap.php";

//function swoole_timer_after($ms, $callback, $param = null) {}
//function swoole_timer_tick($ms, $callback) {}
//function swoole_timer_clear($timer_id) {}

swoole_timer_after(-1, function(){ });
swoole_timer_tick(-1, function() { });
swoole_timer_after(86400001, function(){ });
swoole_timer_tick(86400001, function() { });
swoole_timer_clear(-1);

for ($i = 0; $i < 1000; $i++) {
    swoole_timer_clear(swoole_timer_after(1, function() {}));
}

//swoole_timer_after(1, null);
//swoole_timer_after(1, "strlen");

function sw_timer_pass_ref(&$ref_func) {
    swoole_timer_after(1, $ref_func);
}
$func = function() {};
sw_timer_pass_ref($func);
