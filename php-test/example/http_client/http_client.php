<?php
require_once __DIR__ . "/../../Bootstrap.php";


//$httpClient = new \swoole_http_client("127.0.0.1", 9003);

//make an http_client obj and set cb fun
function makeHttpClient($host = HTTP_SERVER_HOST, $port = HTTP_SERVER_PORT, $ssl = false, $output = false, callable $done = null)
{
$httpClient = new \swoole_http_client($host, $port, $ssl);

$httpClient->set([
    "socket_buffer_size" => 1024 * 1024 * 2,
]);
    /*
    if ($ssl) {
        $httpClient->set([
            'ssl_cert_file' => __DIR__ . '../swoole_http_server/localhost-ssl/server.crt',
            'ssl_key_file' => __DIR__ . '../swoole_http_server/localhost-ssl/server.key',
        ]);
    }
    */

$httpClient->on("connect", function(\swoole_http_client $httpClient) {
    echo "http client: connect.\n";
    //var_dump($httpClient->isConnected());
 });

 $httpClient->on("error", function(\swoole_http_client $httpClient) {
    echo "error.\n";
});

$httpClient->on("close", function(\swoole_http_client $httpClient) {
     echo "connection close.\n";
});

return $httpClient;
}

//test execute: 
//method:NULL or post ;data:NULL or XXX
function testExecute($host, $port, $method, $data, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    if ($data !== false) {
        $httpClient->setData($data);
    }
    if ($method) {
        $httpClient->setMethod("POST");
    }
    $httpClient->execute("/content_length", function(\swoole_http_client $httpClient) use($fin, $data) {
        echo "test execute:\n";
        echo "body: $httpClient->body,data: $data.\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}

function testUri($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->get("/uri", function(\swoole_http_client $httpClient) use($fin) {
        echo "test uri: body $httpClient->body,statusCode $httpClient->statusCode,errCode $httpClient->errCode\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}

function testGet($host, $port, array $query, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);

    $queryStr = http_build_query($query);
    $httpClient->get("/get?$queryStr", function(\swoole_http_client $httpClient) use($query, $queryStr, $fin) {
        // $httpClient->headers;
	    //$ret = json_decode($httpClient->body, true);
        var_dump($query);
        echo "test get: $httpClient->body.\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}


function testPost($host, $port, array $query, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->post("/post", $query, function(\swoole_http_client $httpClient) use($query, $fin) {
        //$ret = json_decode($httpClient->body, true);
        //var_dump($query);
        echo "test post:$httpClient->body.\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}


function testMethod($host, $port, $method, $data = null, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setMethod($method);
    if ($data) {
        $httpClient->setData($data);
    }
    $httpClient->execute("/method", function(\swoole_http_client $httpClient) use($method, $fin) {
        echo "test Method, method body:$httpClient->body, method:$method.\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}

function testCookie($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setCookies(["hello" => "world"]);
    $httpClient->get("/cookie", function(\swoole_http_client $httpClient) use($fin){
        echo "test cookie,http body:$httpClient->body.\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}

function testHeader($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);

    $httpClient->setting += ["keep_alive" => true];
    //set Headers
    $httpClient->setHeaders(["hello" => "world"]);

    $httpClient->get("/header", function(\swoole_http_client $httpClient) use($fin){
        $headers = json_decode($httpClient->body, true);
        echo "test header:\n";
        var_dump($headers);
        //assert(isset($headers["hello"]) && $headers["hello"] === "world");
        if ($fin) {
            $fin($httpClient);
        }
    });
}

function testSleep($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->get("/sleep", function(\swoole_http_client $httpClient) use($fin){
        echo "test sleep:\n";
        var_dump($httpClient->body);
        if ($fin) {
            $fin($httpClient);
        }
    });
}

function testSendfile($host, $port, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setMethod("GET");
    $ok = $httpClient->execute("/file", function(\swoole_http_client $httpClient) use($fin){
        echo "test sendfile:\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
    assert($ok);
}

function testRawCookie($host, $port, $cookie, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setMethod("POST");
    $httpClient->setData($cookie);
    $ok = $httpClient->execute("/rawcookie", function(\swoole_http_client $httpClient) use($fin){
        echo "test rawcookie: body:$httpClient->body.\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}

function testRawcontent($host, $port, $data, callable $fin = null)
{
    $httpClient = makeHttpClient($host, $port);
    if ($data !== false) {
        $httpClient->setData($data);
    }
    $httpClient->setMethod("POST");
    $ok = $httpClient->execute("/rawcontent", function(\swoole_http_client $httpClient) use($data, $fin) {
        echo "test rawcontent: body:$httpClient->body.\n";
        if ($fin) {
            $fin($httpClient);
        }
    });
}

/*
function testrequest($host, $port, $method, $url, $body, array $header, array $cookie, callable $fin)
{
    $httpClient = makeHttpClient($host, $port);
    $httpClient->setMethod($method);
    if ($cookie) {
        $httpClient->setCookies($cookie);
    }
    if ($header) {
        $httpClient->setCookies($header);
    }
    if ($body) {
        $httpClient->setData($body);
    }
    $httpClient->setting += ["keep_alive" => false];
    $httpClient->execute($url, function(\swoole_http_client $httpClient) use($fin) {
        //$fin($httpClient);
        //$httpClient->close();
        echo "test request:body $httpClient->body,statusCode $httpClient->statusCode,errCode $httpClient->errCode";
        if ($fin) {
            $fin($httpClient);
        }
    });
}
*/

