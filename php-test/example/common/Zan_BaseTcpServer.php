<?php

require __DIR__ . "/Zan_ServerTrait.php";

class Zan_BaseTcpServer {
    use Zan_ServerTrait;

    public static function createServer(string $listen_ip = "0.0.0.0", int $listen_port = 9501) {
        $server = new static();
        $server->setListenPort($listen_port);
        $server->setListenIp($listen_ip);

        return $server;
    }

    public function getZanServer() {
        if (null != $this->zan_server) {
            return $this->zan_server;
        }

        $listen_ip   = $this->getListenIp();
        $listen_port = $this->getListenPort();
        $zan_server  = new swoole_server($listen_ip, $listen_port);
        $zan_server->on('Start',        array($this, 'onStart'));
        $zan_server->on('Shutdown',     array($this, 'onShutdown'));
        $zan_server->on('ManagerStart', array($this, 'onManagerStart'));
        $zan_server->on('WorkerStart',  array($this, 'onWorkerStart'));
        $zan_server->on('WorkerStop',   array($this, 'onWorkerStop'));
        $zan_server->on('Close',        array($this, 'onClose'));
        $zan_server->on('Connect',      array($this, 'onConnect'));
        $zan_server->on('Receive',      array($this, 'onReceive'));
        $zan_server->on('Task',         array($this, 'onTask'));
        $zan_server->on('Finish',       array($this, 'onFinish'));
        $zan_server->on('PipeMessage',  array($this, 'onPipeMessage'));
        $zan_server->set($this->getServerConf());

        $this->zan_server = $zan_server;
        return $this->zan_server;
    }

    public function serve() {
        $serv = $this->getZanServer();
        $serv->start();
    }
}
