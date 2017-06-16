<?php

$start = microtime(true);

$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect", function(swoole_client $cli) {
    assert(false);
});
$cli->on("receive", function(swoole_client $cli, $data) {
    assert(false);
});
$cli->on("error", function(swoole_client $cli) {
    global $start;
    echo "error\n";
    echo microtime(true) - $start;
});
$cli->on("close", function(swoole_client $cli) {
    echo "close\n";
});

swoole_timer_after(100, function() {
    echo "time out";
    swoole_event_exit();
});


function refcount($var)
{
    ob_start();
    debug_zval_dump($var);
    preg_match('/refcount\((?<refcount>\d)\)/', ob_get_clean(), $matches);
    return intval($matches["refcount"]) - 3;
}

$cli->connect("11.11.11.11", 9000);
$cli->connect("11.11.11.11", 9000);
$cli->connect("11.11.11.11", 9000);
$cli->connect("11.11.11.11", 9000);
$cli->connect("11.11.11.11", 9000);
// xdebug_debug_zval("cli");
// echo refcount($cli); // php7无效