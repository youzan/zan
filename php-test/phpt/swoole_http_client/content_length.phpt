--TEST--
swoole_http_client: content length

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";
require_once __DIR__ . "/../../apitest/swoole_http_client/simple_http_client.php";

$simple_http_server = __DIR__ . "/../../apitest/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());


$makeDone = function($n, $f) {
    return function() use(&$n, $f) {
        $n--;
        if ($n === 0) {
            $f();
        }
    };
};
$done = $makeDone(3, $closeServer);

$data = null;
testExecute(HTTP_SERVER_HOST, $port, null, $data, function($httpClient) use($data, $done) {
    assert(0 === intval($httpClient->body));
    echo "SUCCESS";
    $done();
});


$data = null;
testExecute(HTTP_SERVER_HOST, $port, "POST", $data, function($httpClient) use($data, $done) {
    assert(0 === intval($httpClient->body));
    echo "SUCCESS";
    $done();
});


$data = RandStr::gen(rand(0, 1024));
testExecute(HTTP_SERVER_HOST, $port, "POST", $data, function($httpClient) use($data, $done) {
    assert(strlen($data) === intval($httpClient->body));
    echo "SUCCESS";
    $done();
});


?>

--EXPECT--
SUCCESSSUCCESSSUCCESS