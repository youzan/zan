<?php

swoole_async_set([
    "disable_dns_cache" => true,
    "dns_lookup_random" => true,
]);

$host = "127.0.0.1";

swoole_async_dns_lookup($host, function($host, $ip) {
    $redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);

    $redis_pool->on("hbConstruct", function() {
        return [
            "method" => "PING"
        ];
    });
    $redis_pool->on("hbCheck", function(\swoole_connpool $pool, $connobj, $data) {
        return true;
    });

    $redis_pool->setConfig([
        "host" => "127.0.0.1",
        "port" => 6379,
    ]);

    $redis_pool->createConnPool(10, 50);

    function get_conn(\swoole_connpool $redis_pool) {
        $id = $redis_pool->get(function(\swoole_connpool $pool, $redis) {
            if ($redis instanceof \swoole_redis) {
                var_dump($redis);
            } else {
                get_conn($pool);
            }
        }, 1);
        echo $id, "\n";
    }

    get_conn($redis_pool);
});
