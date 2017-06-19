<?php
$httpClient = new swoole_http_client("11.11.11.11", 9000);
$httpClient->on("timeout", function(swoole_http_client $cli) {
    echo "timeout\n";
    $cli->close();
});

$httpClient->setReqTimeout(1);
$httpClient->get("/", function ($client)  {
    assert(false);
});
