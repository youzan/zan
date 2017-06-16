<?php



function addTimer(\swoole_http_client $httpClient)
{
    if (property_exists($httpClient, "timeo_id")) {
        return false;
    }
    return $httpClient->timeo_id = swoole_timer_after(1000, function() use($httpClient) {
        debug_log("http request timeout");

        // TODO 超时强制关闭连接 server端: ERROR	swFactoryProcess_finish (ERROR 1005): session#%d does not exist.
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


function testCookieCore(callable $fin = null)
{
    $httpClient = new \swoole_http_client("127.0.0.1", 9002);
    $httpClient->set([
        "socket_buffer_size" => 1024 * 1024 * 2,
    ]);

    $httpClient->on("connect", function(\swoole_http_client $httpClient) {
        assert($httpClient->isConnected() === true);
        // debug_log("connect");
    });

    $httpClient->on("error", function(\swoole_http_client $httpClient) {
        cancelTimer($httpClient);
        // debug_log("error");
    });

    $httpClient->on("close", function(\swoole_http_client $httpClient) {
        cancelTimer($httpClient);
        // debug_log("close");
    });

    addTimer($httpClient);
    $ok = $httpClient->setCookies("hello=world; path=/;");
    assert($ok);

    $ok = $httpClient->get("/cookie", function(\swoole_http_client $httpClient) use($fin) {
        cancelTimer($httpClient);
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        var_dump($httpClient->body);
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}


set_error_handler(function($errno) {
    assert($errno === 4096);
    echo "ERROR";
});

testCookieCore(function()  {
    echo "SUCCESS";
});

