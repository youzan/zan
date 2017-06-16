<?php
/**
 * swoole 3.0.4
 *
 * Linux 环境 (Mac 未测试)
 * TCP Client 收到RST包时候
 * 有概率触发connect回调，然后触发close回调
 */

function rst()
{
    $cli =new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $cli->on("close", function() {
//        echo "rst closed\n";
        rst();
    });
    $cli->on("error", function() {
//        echo "rst error\n";
        rst();
    });
    $cli->on("connect", function(\swoole_client $cli) {
        echo "rst connected\n";
        rst();
    });
    $cli->on("receive", function(\swoole_client $cli, $recv) {
    });
    $cli->connect("127.0.0.1", 1111);
}

function sync()
{
    $cli =new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $cli->on("close", function() { });
    $cli->on("error", function() {
        echo "!!!error!!!!";
    });
    $cli->on("connect", function(\swoole_client $cli) {
//        echo "sync connected\n";
        $cli->close(); sync();
    });
    $cli->on("receive", function(\swoole_client $cli, $recv) {});
    $cli->connect("61.135.169.121", 80);
}

rst();

sync();
