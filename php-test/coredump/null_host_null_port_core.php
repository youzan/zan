<?php
$httpClient = new \swoole_http_client(null, null);
$httpClient->execute("/", function(\swoole_http_client $httpClient) {});