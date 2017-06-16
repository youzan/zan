<?php


function debug_log($str, $handle = STDERR)
{
    if ($handle === STDERR) {
        $tpl = "\033[31m[%d %s] %s\033[0m\n";
    } else {
        $tpl = "[%d %s] %s\n";
    }
    if (is_resource($handle)) {
        fprintf($handle, $tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    } else {
        printf($tpl, posix_getpid(), date("Y-m-d H:i:s", time()), $str);
    }
}


function addTimer(\swoole_http_client $httpClient)
{
    if (property_exists($httpClient, "timeo_id")) {
        return false;
    }
    return $httpClient->timeo_id = swoole_timer_after(1000, function() use($httpClient) {
        debug_log("http request timeout");
        $httpClient->close();
        assert($httpClient->isConnected() === false);
    });
}

function cancelTimer($httpClient)
{
    if (property_exists($httpClient, "timeo_id")) {
        $ret = swoole_timer_clear($httpClient->timeo_id);
        unset($httpClient->timeo_id);
        return $ret;
    }
    return false;
}


class HttpServerTmp
{
    /**
     * @var \swoole_http_server
     */
    public $httpServ;

    public function __construct()
    {
        $this->httpServ = new \swoole_http_server("127.0.0.1", "9002", SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->httpServ->setglobal(HTTP_GLOBAL_ALL, HTTP_GLOBAL_GET | HTTP_GLOBAL_POST | HTTP_GLOBAL_COOKIE);
    }

    public function start()
    {
        $this->httpServ->on('start', [$this, 'onStart']);
        $this->httpServ->on('shutdown', [$this, 'onShutdown']);

        $this->httpServ->on('workerStart', [$this, 'onWorkerStart']);
        $this->httpServ->on('workerStop', [$this, 'onWorkerStop']);
        $this->httpServ->on('workerError', [$this, 'onWorkerError']);

        $this->httpServ->on('connect', [$this, 'onConnect']);
        $this->httpServ->on('request', [$this, 'onRequest']);

        $this->httpServ->on('close', [$this, 'onClose']);

        $this->httpServ->start();
    }

    public function onConnect()
    {
        debug_log("connecting ......");
    }

    public function onClose()
    {
        debug_log("closing .....");
    }

    public function onStart(swoole_server $swooleServer)
    {
        debug_log("server starting .....");
    }

    public function onShutdown(swoole_server $swooleServer)
    {
        debug_log("server shutdown .....");
    }

    public function onWorkerStart(swoole_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId starting .....");
    }

    public function onWorkerStop(swoole_server $swooleServer, $workerId)
    {
        debug_log("worker #$workerId stopping ....");
    }

    public function onWorkerError(swoole_server $swooleServer, $workerId, $workerPid, $exitCode, $sigNo)
    {
        debug_log("worker error happening [workerId=$workerId, workerPid=$workerPid, exitCode=$exitCode, signalNo=$sigNo]...");
    }

    public function onRequest(\swoole_http_request $request, \swoole_http_response $response)
    {
        $uri = $request->server["request_uri"];

        testSetCookie:
        {
            $name = "name";
            $value = "value";
            // $expire = $request->server["request_time"] + 3600;
            $expire = 0;
            $path = "/";
            $domain = "";
            $secure = false;
            $httpOnly = true;
            // string $name [, string $value = "" [, int $expire = 0 [, string $path = "" [, string $domain = "" [, bool $secure = false [, bool $httponly = false ]]]]]]
            $response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
            $expect = "name=value; path=/; httponly";
            assert(in_array($expect, $response->cookie, true));
        }



        if ($uri === "/cookie") {
            if (property_exists($request, "cookie")) {
                $response->end(json_encode($request->cookie));
            } else {
                $response->end("{}");
            }
            return;
        }

        $response->end("Hello World!");
    }
}


if (pcntl_fork() === 0) {
    (new HttpServerTmp())->start();
    exit();
}


sleep(2);



$httpClient = new \swoole_http_client("127.0.0.1", 9002);
$httpClient->set([
    "socket_buffer_size" => 1024 * 1024 * 2,
]);

$httpClient->on("connect", function(\swoole_http_client $httpClient) {
    // cancelTimer($httpClient);
    assert($httpClient->isConnected() === true);
    debug_log("connect");
});

$httpClient->on("error", function(\swoole_http_client $httpClient) {
    cancelTimer($httpClient);
    debug_log("error");
});

$httpClient->on("close", function(\swoole_http_client $httpClient) {
    cancelTimer($httpClient);
    debug_log("close");
});


addTimer($httpClient);
$ok = $httpClient->setCookies("hello=world; path=/;");
assert($ok);

$ok = $httpClient->get("/cookie", function(\swoole_http_client $httpClient) {
    cancelTimer($httpClient);
    assert($httpClient->statusCode === 200);
    assert($httpClient->errCode === 0);
    var_dump($httpClient->body);
    swoole_event_exit();
});
assert($ok);