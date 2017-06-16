<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/24
 * Time: 下午9:02
 */



$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
    "hbIntervalTime" => 100,
//    "hbTimeout" => 1,
]);
assert($r === true);

$tcp_pool->on("hbConstruct", function() {
    return [
        "method" => "send",
        "args" => "GET / HTTP 1.1\r\n\r\n\r\n",
    ];
});
$tcp_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) {
    echo $data, "\n";
    return false;
});


$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);



function get_release($tcp_pool)
{
    $timeout = 1000;

    $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
        assert(false);
        swoole_event_exit();
    });

    $connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
        swoole_timer_clear($timerId);
        if ($cli instanceof \swoole_client) {


            swoole_timer_after(100, function() use($cli, $pool) {
                // assert($cli->isConnected());
                $cli->close(true);
                $pool->release($cli, \swoole_connpool::SWOOLE_CONNNECT_OK);
                get_release($pool);
            });
        } else {
            assert(false);
            swoole_event_exit();
        }
    });

    echo $connId, "\t" , microtime(true), "\n";

    if ($connId === false) {
        assert(false);
        swoole_event_exit();
    }
}

get_release($tcp_pool);