<?php
// 百度不可访问情况

swoole_async_dns_lookup("www.baidu.com", function($host, $ip) {
    $httpClient = new \swoole_http_client($ip, 80);
    $httpClient->set([
        "socket_buffer_size" => 1024 * 1024 * 2,
    ]);

    $httpClient->on("connect", function(\swoole_http_client $httpClient) {
        echo "connected\n";
        assert($httpClient->isConnected() === true);
    });

    $httpClient->on("error", function(\swoole_http_client $httpClient) {
        echo "error\n";
    });

    $httpClient->on("close", function(\swoole_http_client $httpClient) {
        echo "close\n";
    });


//    $method = str_repeat("get", 1024);
    $method = "get";
    $ok = $httpClient->setMethod($method);
    assert($ok);
//    if ($data) {
//        $httpClient->setData($data);
//    }
    $ok = $httpClient->execute("/", function(\swoole_http_client $httpClient) use($method) {
        var_dump($httpClient->body);
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        assert($httpClient->body === $method);
    });
    assert($ok);
});
