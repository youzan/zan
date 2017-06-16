<?php

/**
 * 慢网络情况下，http client 接收 header有问题
 */

$httpClient = new \swoole_http_client("127.0.0.1", 8888);
$httpClient->get("/", function(\swoole_http_client $client) {
    print_r($client->headers);
    // ["A" => "B"];

    print_r($client->body);
});