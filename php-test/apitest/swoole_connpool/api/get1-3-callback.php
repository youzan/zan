<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午8:56
 */

$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$r = $mysql_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 3306,
    "user" => "root",
    "password" => "",
    "database" => "test",
    "charset" => "utf8mb4",

    "hbIntervalTime" => 1,
    "hbTimeout" => 1,
]);

$mysql_pool->on("hbConstruct", function() {
    return [
        "method" => "query",
        "args" => "select sleep(1)",
    ];
});
$mysql_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) { return true; });


assert($r === true);
$r = $mysql_pool->createConnPool(0, 10);
assert($r === true);

function get($mysql_pool)
{
    $timeout = 1000;
    $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
        assert(false);
        swoole_event_exit();
    });
    $connId = $mysql_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/$cli) use($timerId) {
        echo "got\n";
        swoole_timer_clear($timerId);
        if ($cli instanceof \swoole_mysql) {
            assert($cli->isConnected());
            $cli->query("select sleep(1)", function($cli, $r) use($pool) {
                var_dump($r);
                echo "query cb\n";
                $pool->release($cli);
            });
        } else {
            // assert(false);
        }
        get($pool);
//    swoole_event_exit();
    });
//    var_dump($connId);
}

for ($i = 0; $i < 400; $i++) {
    get($mysql_pool);
}