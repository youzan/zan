<?php

$swoole_mysql = new \swoole_mysql();

$swoole_mysql->on("close", function() {
    echo "closed\n";
    swoole_event_exit();
});

$swoole_mysql->on('timeout', function(\swoole_mysql $swoole_mysql, $timeoutType) {
    echo "connect timeout\n";
    assert($timeoutType === SWOOLE_ASYNC_CONNECT_TIMEOUT);
    $swoole_mysql->close();
});

$swoole_mysql->setConnectTimeout(1);

$r = $swoole_mysql->connect([
    "host" => "11.11.11.11",
    "port" => 9000,
    "user" => "root",
    "password" => "admin",
    "database" => "test",
    "charset" => "utf8mb4",
], function (\swoole_mysql $swoole_mysql, $result) {
    assert(false);
});