<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/2/16
 * Time: 上午1:51
 */

$cli = new \swoole_http_client("127.0.0.1", 4161);
function get() {
    global $cli;
    static $zval = [
        "headers" => ["Connection" => "keep-alive"],
        "cookies" => [],
    ];
    echo "~";

    var_dump($zval["cookies"]);
    // ~UNKNOWN:0 // zval 的内存错误
    $cli->setCookies($zval["cookies"]);
    $cli->get("/lookup?topic=zan_mqworker_test", __FUNCTION__);
}
get();