<?php
trait Zan_ServerTrait {
    protected $listen_ip   = '0.0.0.0';
    protected $listen_port = 9501;
    protected $server_conf = array();

    public function getListenIp() {
        return $this->listen_ip;
    }
    public function setListenIp(string $listen_ip) {
        $this->$listen_ip = $listen_ip;
    }
    public function getListenPort() {
        return $this->listen_port;
    }
    public function setListenPort(int $listen_port) {
        $this->listen_port = $listen_port;
    }
    public function getServerConf() {
        return $this->server_conf;
    }
    public function setServerConf(array $server_conf) {
        $this->server_conf = array_merge($this->server_conf, $server_conf);
    }

    protected $zan_server = null;
    public function getZanServer() {
        return $this->zan_server;
    }

    public function onStart(swoole_server $serv) { }

    public function onShutdown(swoole_server $serv) { }

    public function onManagerStart(swoole_server $serv) { }

    public function onWorkerStart(swoole_server $serv, int $worker_id) { }

    public function onWorkerStop(swoole_server $serv, int $worker_id) { }

    public function onConnect(swoole_server $serv, int $worker_id, int $reactor_id) {
        return $this->onConnectCall($serv, $worker_id, $reactor_id);
    }

    public function onClose(swoole_server $serv, int $worker_id, int $reactor_id) {
        return $this->onCloseCall($serv, $worker_id, $reactor_id);
    }

    public function onReceive(swoole_server $serv, int $worker_id, int $reactor_id, string $data) {
        return $this->onReceiveCall($serv, $worker_id, $reactor_id, $data);
    }

    public function onPacket(swoole_server $serv, string $data, array $client_info) {
        return $this->onPacketCall($serv, $data, $client_info);
    }

    public function onTimerTick() { }

    public function onTask(swoole_server $serv, int $task_id, int $worker_id, string $data) { }

    public function onFinish(swoole_server $serv, int $task_id, string $result) { }

    public function onRequest(http_request $request, http_response $response) { }

    public function onPipeMessage(swoole_server $serv, int $worker_id, string $message) { }

    public function onConnectCall(swoole_server $serv, int $worker_id, int $reactor_id) { }

    public function onCloseCall(swoole_server $serv, int $worker_id, int $reactor_id) { }

    public function onReceiveCall(swoole_server $serv, int $worker_id, int $reactor_id, string $data) { }

    public function onPacketCall(swoole_server $serv, string $data, array $client_info) { }

    public function logger(string $data) {
        echo "[" . date('Y-m-d H:i:s') . "]" . " " . get_class() . " " . $data;
    }
}
