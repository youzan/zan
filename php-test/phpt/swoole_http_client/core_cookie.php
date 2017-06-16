<?php

require_once __DIR__ . "/../inc/zan.inc";
require_once __DIR__ . "/../../apitest/swoole_http_client/simple_http_client.php";

$simple_http_server = __DIR__ . "/../../apitest/swoole_http_server/simple_http_server.php";
//$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = freeport());


set_error_handler(function($errno) {
    assert($errno === 4096);
    echo "ERROR";
});

testCookieCore(function()  {
    echo "SUCCESS";
//    $closeServer();
});

//suicide(1000, SIGTERM, $closeServer);