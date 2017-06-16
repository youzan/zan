<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/2/16
 * Time: 上午1:56
 */

// WARNING	http_client_create: Operation now in progress phase 1,or socket is closed
$cli = new \swoole_http_client("127.0.0.1", 4161);
function get() {
    global $cli;
    static $zval = [
        "headers" => ["Connection" => "keep-alive"],
        "cookies" => [],
    ];
    echo "~";

    $cli->setHeaders($zval["headers"]);
    $cli->get("/lookup?topic=zan_mqworker_test", __FUNCTION__);
}
get();exit();