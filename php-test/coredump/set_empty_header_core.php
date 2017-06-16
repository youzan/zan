<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/2/16
 * Time: 上午1:11
 */

$cli = new \swoole_http_client("127.0.0.1", 4161);
function get() {
    global $cli;
    $cli->setHeaders([]);
    $cli->get("/lookup?topic=zan_mqworker_test", __FUNCTION__);
}
get();