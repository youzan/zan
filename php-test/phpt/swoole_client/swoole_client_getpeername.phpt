--TEST--
swoole_client: swoole_client getsockpeername

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
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
 * Time: 上午10:59
 */

require_once __DIR__ . "/../inc/zan.inc";

$simple_tcp_server = __DIR__ . "/../../apitest/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);


suicide(5000);


$cli = new \swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_ASYNC);


$cli->on("connect", function(\swoole_client $cli) {
    // TODO 这里坑爹的同步调用
    // TODO defer 也是同步调用!!!
//     swoole_event_defer(function() use($cli) {
        echo "DEFER\n\n\n\n";
        swoole_timer_after(1, function() use($cli) {
            // var_dump($cli->timeo_id);
            var_dump(swoole_timer_exists($cli->timeo_id));
             echo "ON_CONNECT\n";
            swoole_timer_clear($cli->timeo_id);
            assert($cli->isConnected() === true);
            $cli->send("test");
        });
//     });
});

$cli->on("receive", function(\swoole_client $cli, $data){
    var_dump($data);
    $i = $cli->getpeername();
    assert($i !== false);

    // TODO assert
    var_dump($i);



    $cli->close();
});

$cli->on("error", function(\swoole_client $cli) {
    echo "error";
});

$cli->on("close", function(\swoole_client $cli) {
    swoole_event_exit();
    echo "SUCCESS";
});


// TODO on connect 回调同步调用
$r = $cli->connect(IP_BAIDU, 80);
assert($r);
echo "CONNECT RETURN\n";


$cli->timeo_id = swoole_timer_after(1000, function() use($cli) {
    echo "connect timeout";
    $cli->close();
    assert($cli->isConnected() === false);
});

echo "TIMER_AFTER\n";

?>

--EXPECT--
SUCCESS