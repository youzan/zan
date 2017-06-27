<?php
class Client
{
    private $client;
	
	private $host;
	private $port;
	private $count;
	
    public function __construct($host='127.0.0.1', $port=9501) {
        $this->client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        $this->client->on('Connect', array($this, 'onConnect'));
        $this->client->on('Receive', array($this, 'onReceive'));
        $this->client->on('Close', array($this, 'onClose'));
        $this->client->on('Error', array($this, 'onError'));
		
		$this->host = $host;
		$this->port = $port;
		$this->count = 0;
    }
 
    public function connect() {
        if(!$fp = $this->client->connect($this->host, $this->port , 1)) {
            echo "Error: {$fp->errMsg}[{$fp->errCode}]\n";
            return;
        }
    }
 
    //connect之后,会调用onConnect方法
    public function onConnect($cli) {
		echo "Client onConnect...\n";
		
		$this->client->send("Client onConnect, send some data to server...\n");
	}
 
    public function onClose($cli) {
        echo "Client onClose...\n";
    }
 
    public function onError() {
		echo "Client onError...\n";
    }
 
    public function onReceive($cli, $data) {
        echo "Client Received: ".$data."\n";
		if ($this->count <= 10) {
			$this->client->send("Client onReceive, send some data2 to server...\n");
			$this->count ++;
		}
    }
}
 
$client = new Client('127.0.0.1', 9505);
$client->connect();

