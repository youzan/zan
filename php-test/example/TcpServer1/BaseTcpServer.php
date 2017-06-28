<?php

require __DIR__ . "/../common/Zan_BaseTcpServer.php";

class BaseTcpServer extends Zan_BaseTcpServer {

    protected $param = array();
    public function setParam(array $param) {
        $this->param = $param;
    }
    public function getParam() {
        return $this->param;
    }

    public static function createServer(string $listen_ip = "0.0.0.0", int $listen_port = 9505) {
        return parent::createServer($listen_ip, $listen_port);
    }

    //进程名前缀
    private $base_process_name = 'zan_tcp_server_';
    private $isset_process_name = true;

    //存放master进程pid的文件
    protected $pid_file = '/tmp/';

    public function getZanServer() {
        if (null != $this->zan_server) {
            return $this->zan_server;
        }

        //.......
        $this->setServerConf($this->param);

        $listen_port = $this->getListenPort();
        $process_name = "";

        //set process name
        if(isset($this->param['process_name'])) {
            $process_name = $this->param['process_name'];
        }

        if(empty($process_name)) {
            $this->base_process_name = $this->base_process_name . $listen_port . '_';
            $this->isset_process_name = false;
        } else {
            $this->base_process_name = $this->base_process_name . $process_name . "_" . $listen_port . '_';
        }

        //pid_file name
        if (isset($this->param['pid_file_prefix'])) {
            $this->pid_file = $this->param['pid_file_prefix'] . '_' . $listen_port . '_pid';
        } else {
            $this->pid_file = $this->pid_file . $this->base_process_name . 'pid';
        }

        $this->zan_server = parent::getZanServer();
        return $this->zan_server;
    }

    //master process start
    public function onStart(swoole_server $serv) {
        if($this->isset_process_name) {
            swoole_set_process_name($this->base_process_name . 'master');
        }

        $mypid = $this->getZanServer()->master_pid;
        file_put_contents($this->pid_file, $mypid);

        $this->logger("onStart: master process start, pid=$mypid.\n");
    }

    //manager process start
    public function onManagerStart(swoole_server $serv) {
        $pid = getmypid();
        $this->logger("onManagerStart: manager process start, pid=$pid.\n");

        if($this->isset_process_name) {
            swoole_set_process_name($this->base_process_name . 'Manager');
        }
    }

    protected $worker_id = -1;
    //worker process start
    public function onWorkerStart(swoole_server $serv, int $worker_id) {
        $pid = getmypid();
        $this->worker_id = $worker_id;
        if ($worker_id >= $this->getZanServer()->setting['worker_num']) {
            //task_worker
            if($this->isset_process_name) {
                swoole_set_process_name($this->base_process_name . 'TaskWorker');
            }
            $this->logger("TaskWorker worker_id=$worker_id start, pid=$pid.\n");
        } else {
            //worker process
            if($this->isset_process_name) {
                swoole_set_process_name($this->base_process_name . 'Worker');
            }
            $this->logger("Worker worker_id=$worker_id start, pid=$pid.\n");

            //我们在第一个 worker 进程, worker_id=0 的进程中启动一个定时器
            if (0 == $worker_id) {
                $this->resetTimer(30000);
            }
        }
    }

    protected $timer_id = null;
    protected function resetTimer($ms) {
        if ($this->timer_id && swoole_timer_exists($this->timer_id)) {
            swoole_timer_clear($this->timer_id);
            $this->timer_id = null;
        }
        $this->timer_id = swoole_timer_after($ms, array($this, 'onTimerTick'));
    }

    public function onTimerTick() {
        $this->logger("onTimerTick...\n");

        //TODO::可以在这里做一些需要定时操作的事情

        $this->resetTimer(30000);
    }

    //server shutdown
    public function onShutdown(swoole_server $serv) {
        $this->logger("onShutdown: server shutdown.\n");
        file_put_contents($this->pid_file, '');
    }

    //onReceive event
    public function onReceiveCall(swoole_server $serv, int $worker_id, int $reactor_id, string $data) {
        $this->logger("onReceiveCall: worker_id=$worker_id, reactor_id=$reactor_id,data=$data\n");

        //TODO::这里可以做一些数据处理的事情
        $task_data = $data;

        //for test
        $serv->send($worker_id, "Server send some data to client.");
    }

    public function logger(string $data) {
        echo "[" . date('Y-m-d H:i:s') . "]" . " " . get_class() . " " . $data;
    }
}
