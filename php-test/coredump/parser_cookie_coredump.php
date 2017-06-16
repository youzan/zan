<?php
require_once __DIR__ . "/../Bootstrap.php";
require_once __DIR__ . "/../../apitest/swoole_http_client/simple_http_client.php";

$simple_http_server = __DIR__ . "/../../apitest/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, HTTP_SERVER_PORT);


set_error_handler(function($errno) {
    assert($errno === 4096);
    echo "ERROR";
});

testCookieCore(function() use($closeServer) {
    echo "SUCCESS";$closeServer();
});

suicide(1000, SIGTERM, $closeServer);