<?php
$serv = new swoole_server("0.0.0.0", 9501);
$serv->set(array(
		'worker_num' => 1,
        'reactor_num'  => 4,
        'open_length_check' => 1,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 0,
        'package_max_length'  => 8192000,
		'max_request' => 10,
        'log_level' => 5,
//		'daemonize' => true,
//		'log_file' => './swoole.log',
));

$serv->on('start', function($serv) {
    $pid = posix_getpid();
    echo "start:$pid\n";

});

$serv->on('shutdown', function($serv) {
    $pid = posix_getpid();
    echo "shutdown:$pid\n";
});

$serv->on('workerStart', function($serv, $worker_id) {
    $pid = posix_getpid();
	echo "worker start:$pid\n";
});

$serv->on('connect', function ($serv, $fd, $from_id){
    $pid = posix_getpid();
    echo "onConnect:$pid\n";
});

$serv->on('receive', function(swoole_server $server, $fd, $from_id, $data)
{
    $pid = posix_getpid();
    echo "onReceive1:$pid\n";
    // echo mb_strlen($data) . "\n";
    //echo $seq_no. "\n";
    if(nova_decode($data,$service_name, $method_name, $ip, $port, $seq_no, $attachData, $relData))
    {
        echo "decode success\n";
        echo "service_name: $service_name; method_name:$method_name; ip:$ip; port:$port; seqno:$seq_no; attach:$attachData\n";
        $buf = "Welcome to access service";
        $sendBuf = "";
        $rand = rand(1,3);
        sleep($rand);
        if (nova_encode($service_name, $method_name, $ip, $port, $seq_no, "{}", $buf, $sendBuf))
        {
            echo "encode success\n";
            $server->send($fd, $sendBuf);
           // sleep(2);
            //$server->deny_request(1);
            //sleep(2);
            //$server->exit();
        } else {
            echo "encode failer\n";
        }
    } else {
        echo "decode failer\n";
    }
});

$serv->on('close', function ($serv, $fd, $from_id) {
    $pid = posix_getpid();
    echo "onClose:$pid\n";
});
$set = [
    'module' => 'stest',
    'enable_hawk' => 1,
    'hawk_url' =>  'http://192.168.66.202:9299/report',
    'timeout'          => 100,
    'services' =>
    [
        [
            'service' => 'com.youzan.xxx',
            'methods' => ['getAdmin', 'getLoad']
        ],
        [
            'service' => 'com.youzan.stest.api.DemoDomainService',
            'methods' => ['delDemo', 'addDemo']
        ],
        [
            'service' => 'test',
            'methods' => ['test']
        ]
    ]
];
$serv->nova_config($set);

$serv->start();

?>
