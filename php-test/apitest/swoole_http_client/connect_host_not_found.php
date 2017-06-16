<?php

$cli = new \swoole_http_client("11.11.11.11", 9000);

$cli->on('close', function($cli) {
    assert(false);
});

$cli->on('error', function($cli) {
    echo "error";
});

swoole_timer_after(100, function() {
    echo "time out";
    swoole_event_exit();
});
$cli->get('/', function(swoole_http_client $cli) {});