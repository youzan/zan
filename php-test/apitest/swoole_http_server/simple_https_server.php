<?php


require_once __DIR__ . "/http_server.php";


/*
class swoole_http_server extends swoole_server
{
    public function on($name, $cb) {} // 与 tcp server 的on接受的eventname 不同
}
class swoole_http_response
{
    public function cookie() {}
    public function rawcookie() {}
    public function status() {}
    public function gzip() {}
    public function header() {}
    public function write() {}
    public function end() {}
    public function sendfile() {}
}
class swoole_http_request
{
public function rawcontent() {}
}
 */

$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;

(new HttpServer($host, $port, true))->start();