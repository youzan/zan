<?php

// zan 未使用
//function swoole_event_add($fd, $cb) {}
//function swoole_event_set() {}
//function swoole_event_del($fd) {}
//function swoole_event_write($fd, $data) {}
//function swoole_event_wait() {}

//function swoole_event_exit() {}

require_once __DIR__ . "/../../Bootstrap.php";


swoole_timer_tick(1, function() {
    echo "tick\n";
    swoole_event_exit();
});
