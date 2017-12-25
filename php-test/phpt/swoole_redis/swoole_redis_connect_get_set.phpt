--TEST--
swoole_redis: connect & get & set
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";
//require_once __DIR__ . "/../../apitest/swoole_redis/simple_redis.php";

$redis = new swoole_redis;

$redis->on('Close', function (swoole_redis $redis) {
    echo "onClose\n";
});


$redis->connect('127.0.0.1', 6379, function ($redis, $result) {
    $redis->set('test_key', 'test_value', function ($redis, $result) {
        $redis->get('test_key', function ($redis, $result) {
            echo "test_key=$result\n";
            $redis->close();
        });
    });
});

?>
--EXPECT--
test_key=test_value
onClose