--TEST--
swoole_conn_pool: get release mixed

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
 * Date: 17/5/24
 * Time: 下午9:02
 */

ini_set("memory_limit", -1);

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => IP_BAIDU, // baidu
    "port" => 80,
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);


// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);
$r = $redis_pool->setConfig([
    "host" => REDIS_SERVER_HOST,
    "port" => REDIS_SERVER_PORT,
]);
assert($r === true);
$r = $redis_pool->createConnPool(1, 1);
assert($r > 0);

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$r = $mysql_pool->setConfig([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
]);
assert($r === true);
$r = $mysql_pool->createConnPool(1, 1);
assert($r > 0);

// -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


///*
function get_release($pool, $className)
{
    $timeout = 1000;

//    $timerId = swoole_timer_after($timeout + 100, function() {
//        assert(false);
//        swoole_event_exit();
//    });

    $connId = $pool->get($timeout, function(\swoole_connpool $pool,  $cli) use($className) {
        // swoole_timer_clear($timerId);

        // swoole_timer_after(1, function() use($cli, $className, $pool) {
        if (is_object($cli) && get_class($cli) === $className) {
            assert($cli->isConnected());
            // $cli->close(true);
            if (rand(0, 1)) {
                $pool->release($cli);
            } else {
                $pool->release($cli, \swoole_connpool::SWOOLE_CONNNECT_ERR);
            }
        } else {
            if ($cli !== false) {
                var_dump($className);
                var_dump($cli);
            }
        }

        get_release($pool, $className);
        // });
    });
    assert($connId !== false);
}

for ($i = 0; $i < 100; $i++) {
    // get_release($tcp_pool, \swoole_client::class);

    get_release($redis_pool, \swoole_redis::class);

    // get_release($mysql_pool, \swoole_mysql::class);
}

//*/


/*
function get_release($pool)
{
    $timeout = 1000;

    $connId = $pool->get($timeout, "get_callback");
    assert($connId !== false);
}


function get_callback(\swoole_connpool $pool,  $cli)
{
    if (is_object($cli)) {
        assert($cli->isConnected());
        if (rand(0, 1)) {
            $pool->release($cli);
        } else {
            $pool->release($cli, \swoole_connpool::SWOOLE_CONNNECT_ERR);
        }
    } else {
    }

    get_release($pool);
}



for ($i = 0; $i < 1000000; $i++) {
    // get_release($tcp_pool);

    get_release($redis_pool);

    // get_release($mysql_pool);
}
*/

swoole_timer_after(5000, function() {
    swoole_event_exit();
    echo "SUCCESS";
});

?>

--EXPECT--
SUCCESS