<?php

/**
 * swoole 3.0.4
 * mysql client 接收RST包 情况下 依次触发connect与close回调
 * connect 回调第二个参数为true， 不符合预期
 */

$mysql = new \swoole_mysql();

$server = [
    "host" => "127.0.0.1",
    "port" => 9999, // RST
    "user" => "root",
    "password" => "",
    "database" => "test"
];

$mysql->on("close", function() { echo "close\n"; });

$mysql->connect($server, function ($db, $r) {
    var_dump($db->connect_errno, $db->connect_error);

    // assert($r === false);
    var_dump($r);
});