<?php

function send_timeout($host, $port)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $cli->on("timeout", function(swoole_client $cli, $timeoutType) {
        assert($timeoutType === SWOOLE_ASYNC_CONNECT_TIMEOUT);
        echo "connect timeout\n";
        $cli->close();
    });

    $cli->setConnectTimeout(5000);
    $cli->on("connect", function(swoole_client $cli) {
        $data = str_repeat('a', 6553600);
        $cli->send($data);
    });

    $cli->on("receive", function(swoole_client $cli, $data) {
        assert(false);
    });
    $cli->on("error", function(swoole_client $cli) { echo "error\n"; });
    $cli->on("close", function(swoole_client $cli) { echo "close\n"; });
    $cli->on("timeout", function(swoole_client $cli, $timeoutType) {
        assert($timeoutType === SWOOLE_ASYNC_RECV_TIMEOUT);
        echo "send timeout\n";
        $cli->close();
    });

    $cli->setSendTimeout(1);
    $cli->connect($host, $port);
}