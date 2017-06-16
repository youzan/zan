<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/23
 * Time: 上午11:51
 */





$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);


$timeout = 1000;
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});
$connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
    swoole_timer_clear($timerId);
    if ($cli instanceof \swoole_client) {

/*
$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect", function(swoole_client $cli) {
    assert($cli->isConnected() === true);
    $r = $cli->getSocket();
    assert(is_resource($r));
});
$cli->on("receive", function(swoole_client $cli, $data){ });
$cli->on("error", function(swoole_client $cli) { });
$cli->on("close", function(swoole_client $cli) { });
$cli->connect("180.97.33.107", 80);
return;
*/
        // TODO 这里返回类型不对。。。。
        $sock = $cli->getSocket();
        assert(is_resource($sock));
        // var_dump(socket_close($sock));

        $cli->close(true);
        $pool->release($cli);



        // TODO coredump
        // 释放之后重新获取该连接
        $timeout = 1000;
        $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
            assert(false);
            swoole_event_exit();
        });

        $connId = $pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
            swoole_timer_clear($timerId);
            if ($cli instanceof \swoole_client) {
                assert($cli->isConnected());
            } else {
                assert(false);
            }
            swoole_event_exit();
        });
        assert($connId > 0);

        if ($connId === false) {
            swoole_event_exit();
        }

    } else {
        assert(false);
        swoole_event_exit();
    }
});
assert($connId > 0);

