<?php
$serv = new swoole_server("127.0.0.1", 9501);
$serv->set(array(
    'worker_num' => 2,   //工作进程数量
    //'task_worker_num' =>1,
    'daemonize' => false, //是否作为守护进程
    'networker_num' => 2,
    'heartbeat_idle_time' => 10,
    'heartbeat_check_interval' =>5,
));
$serv->on('connect', function ($serv, $fd){
    echo "Client:Connect.\n";
    //$serv->send($fd, 'Swoole: hello');
});

$serv->on('receive', function ($serv, $fd, $from_id, $data) {
	$serv->send($fd, 'Swoole: '.$data);
	//$start_fd = 0;
	//$index = 0;
	//while($index < 2)
	//{
	// $conn_list = $serv->getClientlist($start_fd, 2);
	 //if($conn_list===false or count($conn_list) === 0)
         //{
        //    echo "finish\n";
        //    break;
        // }
	//$start
	//_fd = end($conn_list);
          // var_dump($conn_list);
	//  $serv->send($conn_list, "broadcast");
	//  $index = $index + 1;

//	}
	//$serv->close($fd);
	$close_connection = 1;
	$serv->heartbeat(1);
});



$serv->on('close', function ($serv, $fd) {
	// echo "Client: Close.\n";
});
$serv->start();
