<?php
require __DIR__ . "/../../Bootstrap.php";
require_once __DIR__ . "/http_client.php";
$simple_http_server = __DIR__ . "/../../apitest/swoole_http_server/simple_http_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

//$host = "127.0.0.1";
//$port = 9003;

$makeFin = function($n, $f) {
    return function() use(&$n, $f) {
        $n--;
        if ($n === 0) {
            $f();
        }
    };
};
$fin = $makeFin(11, $closeServer);


$data = RandStr::gen(rand(0, 1024));
testExecute(HTTP_SERVER_HOST, $port, "POST", $data, function($httpClient) use($closeServer,$fin) {
    echo "finish test execute.\n";
    $fin();
});
//exit;

testUri(HTTP_SERVER_HOST, $port, function($httpClient) use($closeServer,$fin) {
    echo "finish test uri.\n";
    $fin();
});

testGet(HTTP_SERVER_HOST, $port, [], function($httpClient) use($closeServer,$fin) {
    echo "finish test get1.\n";
    $fin();
});
testGet(HTTP_SERVER_HOST, $port, $_SERVER, function($httpClient) use($closeServer,$fin) {
    echo "finish test get2.\n";
    $fin();
});

testPost(HTTP_SERVER_HOST, $port, $_SERVER, function($httpClient) use($closeServer,$fin) {
    echo "finish test post.\n";
    $fin();
});

testMethod(HTTP_SERVER_HOST, $port, "GET", function($httpClient) use($closeServer,$fin) {
    echo "finish test method get.\n";
    $fin();
});
testMethod(HTTP_SERVER_HOST, $port, "DELETE", function($httpClient) use($closeServer,$fin) {
    echo "finish test method delete.\n";
    $fin();
});

testMethod(HTTP_SERVER_HOST, $port, "POST", "payload", function($httpClient) use($closeServer,$fin) {
    echo "finish test method post payload.\n";
    $fin();
});
//testMethod(HTTP_SERVER_HOST, $port, "PUT", "payload");
//testMethod(HTTP_SERVER_HOST, $port, "PATCH", "payload");

// testMethod(HTTP_SERVER_HOST, $port, "GET", "http_body");
// testMethod(HTTP_SERVER_HOST, $port, "DELETE", "http_body");
//testMethod(HTTP_SERVER_HOST, $port, "POST", null);
//testMethod(HTTP_SERVER_HOST, $port, "PUT", null);
//testMethod(HTTP_SERVER_HOST, $port, "PATCH", null);


testCookie(HTTP_SERVER_HOST, $port, function($httpClient) use($closeServer,$fin) {
    echo "finish test cookie.\n";
    $fin();
});
testHeader(HTTP_SERVER_HOST, $port, function($httpClient) use($closeServer,$fin) {
    echo "finish test header.\n";
    $fin();
});
testSleep(HTTP_SERVER_HOST, $port, function($httpClient) use($closeServer,$fin) {
    echo "finish test sleep.\n";
    $fin();
});

/*
$header = ["header_key" => "header_value"];
$cookie = ["header_key" => "header_value"];
testrequest($host, $port, "GET", "/", null, $header, $cookie, function($httpClient) use($closeServer,$fin) {
    echo "finish test request.\n";
    $fin();
});
*/

