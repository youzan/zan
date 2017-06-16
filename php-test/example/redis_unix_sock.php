<?php

$redis = new \swoole_redis();
$redis->connect("/var/run/yz-tether/redis2aerospike.sock", null, function(\swoole_redis $redis) {
    echo "connected\n";
    $redis->set("youzan:knowledge_lib_foo:bar", "value", function($redis, $result) {
        var_dump($result);
        $redis->get("youzan:knowledge_lib_foo:bar", function($redis, $result) {
            var_dump($result);
        });
    });
});

//$socket = new swoole_client(SWOOLE_SOCK_UNIX_STREAM, SWOOLE_SOCK_ASYNC);
//$socket->on("connect", function(swoole_client $cli) {
//    echo "connect\n";
//    $cli->send("*1\r\n$4\r\nPING\r\n");
//});
//$socket->on("receive", function(swoole_client $cli, $data) {
//    echo $data, "\n";
//});
//$socket->on("close", function() {
//   echo "close\n";
//});
//$socket->on("error", function() {
//   echo "error\n";
//});
//$socket->connect("/var/run/yz-tether/redis2aerospike.sock");