<?php

require_once __DIR__ . "/../../Bootstrap.php";


$cli = new swoole_http_client("115.239.211.112", 80);
$cli->setHeaders(["Connection" => "close"]);
$cli->get("/", function(swoole_http_client $cli) {
    echo "receive:", $cli->body, "\n";
});