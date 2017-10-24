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
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/6/7
 * Time: 上午11:15
 */
require_once __DIR__ . "/../inc/zan.inc";


$pid = pcntl_fork();
if ($pid < 0) {
    echo "ERROR";
    exit;
}

if ($pid === 0) {
    $redis = new \swoole_redis();
    $redis->on("close", function() {
         //echo "onClose1";
    });

    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function(\swoole_redis $redis, $r) {
        $r = $redis->publish("test_on_message", "payload!!!", function(\swoole_redis $redis, $r) {
            assert($r);
            $redis->close();
        });
    });

} else {

    $redis = new \swoole_redis();
    $redis->on("close", function() {
        //echo "onClose2";
    });

    $redis->on("message", function(\swoole_redis $redis, $message) use($pid) {
        //var_dump($message);

        if (0 == strcasecmp($message[2], "payload!!!")) {
            //sleep(1);
            echo "SUCCESS\n";
            $redis->close();
        }
    });

    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function(\swoole_redis $redis, $r) {
        assert($r);
        $redis->subscribe("test_on_message");
    });
}

?>
--EXPECT--
SUCCESS