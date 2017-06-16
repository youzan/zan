--TEST--
swoole_conn_pool: get 1 - 2 parallel

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
 * Time: 下午8:56
 */

$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);
$r = $redis_pool->setConfig([
    "host" => REDIS_SERVER_HOST,
    "port" => REDIS_SERVER_PORT,
]);
assert($r === true);
$r = $redis_pool->createConnPool(1, 1);
assert($r === true);



function getOne($redis_pool)
{
    $timeout = 1000;

    $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
        assert(false);
        swoole_event_exit();
    });

    $connId = $redis_pool->get($timeout, function(\swoole_connpool $pool, $cli) use($timerId) {
        swoole_timer_clear($timerId);
        if ($cli instanceof \swoole_redis) {
            assert($cli->isConnected());

            $cli->get("a", function() use($pool, $cli) {
                swoole_timer_after(10, function() use($pool, $cli) {
                    $pool->release($cli);
                    getOne($pool);
                });
            });

        } else {
            getOne($pool);
        }
    });
    // var_dump($connId);
}


getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);
getOne($redis_pool);


swoole_timer_after(5000, function() {
    swoole_event_exit();
    echo "SUCCESS";
//    posix_kill(getmypid(), SIGKILL);
});

?>

--EXPECT--
SUCCESS