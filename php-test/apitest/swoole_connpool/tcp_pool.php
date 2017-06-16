<?php

// `nc -lk 9001`


$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$tcp_pool->on("hbConstruct", function() { return "PING"; });
$tcp_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) { var_dump($data); });
$tcp_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 9001,
]);

$tcp_pool->createConnPool(20, 50);

$connId = $tcp_pool->get(function(\swoole_connpool $pool, \swoole_client $client) {
    $pool->release($client);
}, 100);