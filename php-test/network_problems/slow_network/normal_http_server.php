<?php

(new HttpServer())->start();

class HttpServer
{
    public $http;

    public function __construct()
    {
        $this->http = new \swoole_http_server("0.0.0.0", 8888, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->http->set(["worker_num" => 1]);
    }

    public function start()
    {
        $this->http->on('start', [$this, 'onStart']);
        $this->http->on('shutdown', [$this, 'onShutdown']);
        $this->http->on('workerStart', [$this, 'onWorkerStart']);
        $this->http->on('workerStop', [$this, 'onWorkerStop']);
        $this->http->on('workerError', [$this, 'onWorkerError']);
        $this->http->on('connect', [$this, 'onConnect']);
        $this->http->on('request', [$this, 'onRequest']);
        $this->http->on('close', [$this, 'onClose']);
        $this->http->start();
    }

    public function onStart(\swoole_http_server $http) { }
    public function onShutdown(\swoole_http_server $http){ }
    public function onWorkerStart(\swoole_http_server $http, $workerId){ }
    public function onWorkerStop(\swoole_http_server $http, $workerId) {}
    public function onWorkerError(\swoole_http_server $http, $workerId, $workerPid, $exitCode, $sigNo) { }
    public function onConnect() { }
    public function onClose() { }
    public function onRequest(\swoole_http_request $request, \swoole_http_response $response)
    {
        $response->status(200);
        $response->end(json_encode($request->header));
    }
}