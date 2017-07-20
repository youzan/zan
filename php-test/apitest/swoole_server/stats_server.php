<?php

require_once __DIR__ . "/../../Bootstrap.php";

$host = isset($argv[1]) ? $argv[1] : HTTP_SERVER_HOST;
$port = isset($argv[2]) ? $argv[2] : HTTP_SERVER_PORT;
$port1 = isset($argv[3]) ? $argv[3] : null;
$port2 = isset($argv[4]) ? $argv[4] : null;

(new StatsServer($host, $port, $port1, $port2))->start();

class StatsServer
{
    /**
     * @var \swoole_server
     */
    public $swooleServer;

    public function __construct($host, $port, $port1 = null, $port2 = null)
    {
	    $this->swooleServer = new \swoole_server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        $this->swooleServer->set([
            'worker_num' => 2,
            'task_worker_num' => 2,
        ]);
    }

    public function start($lifetime = 1000)
    {
        $this->lifetime = $lifetime;

        $this->swooleServer->on('start', [$this, 'onStart']);
        $this->swooleServer->on('shutdown', [$this, 'onShutdown']);

        $this->swooleServer->on('workerStart', [$this, 'onWorkerStart']);
        $this->swooleServer->on('receive', [$this, 'onReceive']);
        $this->swooleServer->on('task', [$this, 'onTask']);
        $this->swooleServer->on('finish', [$this, 'onFinish']);

        $this->swooleServer->start();
    }

    public function onStart(\swoole_server $swooleServer) { }
    public function onShutdown(\swoole_server $swooleServer) { }
    public function onWorkerStart(\swoole_server $swooleServer, $workerId)
    {
        if ($workerId === 0) {
            swoole_timer_after($this->lifetime, function() {
                $this->swooleServer->shutdown();
            });
        }
    }
    public function onReceive(\swoole_server $swooleServer, $fd, $fromReactorId, $recv)
    {
        list($op, $args) = opcode_decode($recv);

        switch($op) {
            case "task":
                $swooleServer->task("123");
                return;

            case "reload":
                $this->swooleServer->reload();
                return;
            case "stats":
                $r = $swooleServer->stats();
                $r = $swooleServer->send($fd, opcode_encode("return", $r));
                assert($r !== false);
                return;

            default:
        }
    }

    public function onTask(\swoole_server $swooleServer, $taskId, $fromWorkerId, $recv)
    {
        assert(json_last_error() === JSON_ERROR_NONE);
        return $recv;
    }

    public function onFinish(\swoole_server $swooleServer, $taskId, $recv)
    {
    }
}
