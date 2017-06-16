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
    suicide(2000);

    $redis = new \swoole_redis();
    $redis->on("close", function() {
        // echo "close";
    });
    $timerid = swoole_timer_after(1000, function() {
        echo "ERROR";
        swoole_event_exit();
    });

    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function(\swoole_redis $redis, $r) use($timerid) {
        swoole_timer_clear($timerid);
        assert($r);

        // TODO BUG
        $r = $redis->publish("test_on_message", "payload!!!", function(\swoole_redis $redis, $r) {
            // TODO
            var_dump($redis);
            var_dump($r);
        });
        assert($r);

        swoole_timer_after(500, function() {
            swoole_event_exit();
            exit;
        });
    });
} else {
    suicide(3000);
    $redis = new \swoole_redis();
    $redis->on("close", function() {
        echo "close";
    });
    $redis->on("message", function(\swoole_redis $redis, $message) use($pid) {
        // TODO
        var_dump($message);
        assert($message !== false);
        assert($message[2] === "payload!!!");

        pcntl_waitpid($pid, $status);
        swoole_event_exit();
    });

    $timerid = swoole_timer_after(1000, function() {
        echo "ERROR";
        swoole_event_exit();
    });

    $redis->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT, function(\swoole_redis $redis, $r) use($timerid) {
        swoole_timer_clear($timerid);
        assert($r);

        $redis->subscribe("test_on_message");
    });
}


?>
--EXPECT--
SUCCESS