--TEST--
swoole_conn_pool: create conn pool 3 - 2

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";

/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:15
 */


require_once __DIR__ . "/connSizeTest.php";

// 测试连接创建数量

$configGroup = [
    [
        "host" => REDIS_SERVER_HOST,
        "port" => REDIS_SERVER_PORT,
    ],
    [
        "host" => REDIS_SERVER_HOST1,
        "port" => REDIS_SERVER_PORT1,
    ],
    [
        "host" => REDIS_SERVER_HOST2,
        "port" => REDIS_SERVER_PORT2,
    ],
    [
        "host" => REDIS_SERVER_HOST3,
        "port" => REDIS_SERVER_PORT3,
    ],
];

function dns_lookup_group(array $configGroup, callable $callback, $i = 0)
{
    $c = count($configGroup);
    if ($i < $c) {
        swoole_async_dns_lookup($configGroup[$i]["host"], function($_, $ip) use($i, $configGroup, $callback) {
            $configGroup[$i]["host"] = $ip;
            dns_lookup_group($configGroup, $callback, $i + 1);
        });
    } else {
        $callback($configGroup);
    }
}

dns_lookup_group($configGroup, function(array $configGroup) {
    $test = makeGroupConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_REDIS, $configGroup);
    $test();
});

?>

--EXPECT--
SUCCESS