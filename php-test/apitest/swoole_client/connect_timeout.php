<?php
$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect", function(swoole_client $cli) {
    assert(false);
});
$cli->on("receive", function(swoole_client $cli, $data) {
    assert(false);
});
$cli->on("error", function(swoole_client $cli) { echo "error\n"; });
$cli->on("close", function(swoole_client $cli) { echo "close\n"; });
$cli->on("timeout", function(swoole_client $cli, $timeoutType) {
    assert($timeoutType === SWOOLE_ASYNC_CONNECT_TIMEOUT);
    echo "connect timeout\n";
    $cli->close();
});

$cli->setConnectTimeout(1);
$cli->connect("11.11.11.11", 9000);