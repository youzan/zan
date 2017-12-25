--TEST--
swoole_http_client: set cookie zval引用计数处理错误?

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

$cli = new \swoole_http_client("127.0.0.1", 4161);
$cli->on("error", function() { /*echo "ERROR";*/ swoole_event_exit(); });
$cli->on("close", function() { /*echo "CLOSE";*/ swoole_event_exit(); });

function get() {
    static $i;
    global $cli;
    static $zval = [
        "headers" => ["Connection" => "keep-alive"],
        "cookies" => [],
    ];

    $cli->setCookies($zval["cookies"]);
     echo "SUCCESS";
    if ($i++ > 10) {
        echo "SUCCESS";
        swoole_event_exit();
    } else {
        if ($zval["cookies"] !== []) {
            echo "ERROR";
            swoole_event_exit();
            exit();
        }
        // var_dump($zval["cookie"]);
        // ~UNKNOWN:0 // zval 的内存错误
        $cli->get("/lookup?topic=zan_mqworker_test", __FUNCTION__);
    }
}
get();
swoole_event_wait();
?>

--EXPECT--
SUCCESS
