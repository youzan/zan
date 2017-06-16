--TEST--
swoole_client: getSocket debug

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

$simple_tcp_server = __DIR__ . "/../../apitest/swoole_server/simple_server.php";
start_server($simple_tcp_server, TCP_SERVER_HOST, TCP_SERVER_PORT);

suicide(1000);

$cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

$cli->on("connect", function(swoole_client $cli) {
    swoole_timer_clear($cli->timeo_id);
    // getSocket BUG
    $cli->getSocket();
    $cli->getSocket();
    
    echo "SUCCESS";
    /*
    @$cli->getSocket();
    $err = error_get_last();
    assert($err["message"] === "swoole_client::getSocket(): unable to obtain socket family Error: Bad file descriptor[9].");
    */
     swoole_event_exit();
    
});

$cli->on("receive", function(swoole_client $cli, $data){});
$cli->on("error", function(swoole_client $cli) {});
$cli->on("close", function(swoole_client $cli) {});

$cli->connect(TCP_SERVER_HOST, TCP_SERVER_PORT);
$cli->timeo_id = swoole_timer_after(1000, function() use($cli) {
    debug_log("connect timeout");
    $cli->close();
    assert($cli->isConnected() === false);
});
?>

--EXPECT--
SUCCESS
