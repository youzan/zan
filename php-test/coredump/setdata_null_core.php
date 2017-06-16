<?php


function debug_log($str, $handle = STDERR)
{
    if ($handle === STDERR) {
        $tpl = "\033[31m[%d %s] %s\033[0m\n";
    } else {
        $tpl = "[%d %s] %s\n";
    }
    if (is_resource($handle)) {
        fprintf($handle, $tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    } else {
        printf($tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    }
}


function addTimer(\swoole_http_client $httpClient)
{
    if (property_exists($httpClient, "timeo_id")) {
        return false;
    }
    return $httpClient->timeo_id = swoole_timer_after(1000, function() use($httpClient) {
        debug_log("http request timeout");
        $httpClient->close();
        assert($httpClient->isConnected() === false);
    });
}

function cancelTimer($httpClient)
{
    if (property_exists($httpClient, "timeo_id")) {
        $ret = swoole_timer_clear($httpClient->timeo_id);
        unset($httpClient->timeo_id);
        return $ret;
    }
    return false;
}



$httpClient = new \swoole_http_client("127.0.0.1", 9002);
$httpClient->set([
    "socket_buffer_size" => 1024 * 1024 * 2,
]);

$httpClient->on("connect", function(\swoole_http_client $httpClient) {
    // cancelTimer($httpClient);
    assert($httpClient->isConnected() === true);
    debug_log("connect");
});

$httpClient->on("error", function(\swoole_http_client $httpClient) {
    cancelTimer($httpClient);
    debug_log("error");
});

$httpClient->on("close", function(\swoole_http_client $httpClient) {
    cancelTimer($httpClient);
    debug_log("close");
});



addTimer($httpClient);
// TODO core
$ok = $httpClient->setData(null);
assert($ok);


$ok = $httpClient->get("/header", function(\swoole_http_client $httpClient) {
    cancelTimer($httpClient);
    assert($httpClient->statusCode === 200);
    assert($httpClient->errCode === 0);
    var_dump($httpClient->body);
});
assert($ok);