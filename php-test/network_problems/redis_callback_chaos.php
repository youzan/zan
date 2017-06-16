<?php

/**
 * swoole 3.0.4
 */

/*

超时调用redisClien::close 之后，connect 回调会被调到

-------------
on Connect callback
error
-------------
on Connect callback
error
-------------
on Connect callback
error
-------------
on Connect callback
error
-------------
on Connect callback
error

*/

$storage = new \SplObjectStorage();

function redis_timeout()
{
    global $storage;

    $redis = new \swoole_redis();
    $redis->on("close", function() { echo "closed\n"; });

    $storage->attach($redis);

    $redis->connect("203.98.7.65", 6602, function(\swoole_redis $redis, $connected) use($storage) {
        assert(isset($storage[$redis]) === false);
        echo "-------------\n";
        echo "on Connect callback\n";
        if (!$connected) {
            echo "error\n";
        }
    });
    swoole_timer_after(1, function() use($redis, $storage) {
        // echo "timeout\n";
        $r = $redis->close();
        assert($r === true);

        assert(isset($storage[$redis]));
        $storage->detach($storage);

        redis_timeout();
    });
}

redis_timeout();