<?php
$service = array(
    1=>'com.youzan.xxx',
    2=>'com.youzan.stest.api.DemoDomainService',
    3=>'test',
//    4=>'mytest'
);
$method = array(
    1=>array(
        1=>'getAdmin',
        2=>'getLoad',
//        3=>'getUser',
    ),
    2=>array(
        1=>'delDemo',
        2=>'addDemo',
 //       3=>'hello'
    ),
    3=>array(
        1=>'test',
//      2=>'mytest'
    ),
//    4=>array(
//        1=>'test',
//        2=>'mytest'
//    )
);
$cli = new swoole_client(SWOOLE_SOCK_TCP);
$cli->set(array(
    'open_length_check' => 1,
    'package_length_type' => 'N',
    'package_length_offset' => 0,
    'package_body_offset' => 0,
    'package_max_length'  => 8192000,
 ));
try {


//$cli->connect('172.16.6.213',28004, 4);
if(!$cli->connect('127.0.0.1',9501, 5))
//if(!$cli->connect('172.17.9.61', 9501, 4))
{
    echo "connect error\n";
    echo socket_strerror($cli->errCode) . "\n";
    return -1;
}
} catch(Exception $exception)
{
    echo "catch exception...";

}
// $buf = "hello";
$i=0;
while (true)
//while($i < 10)
{
    echo ++$i . "\n";
    $serviceid = rand(1,count($service));
    $methodid = 1;
    switch($serviceid) {
    case 1:
    case 2:
        $methodid = rand(1,count($method[$serviceid]));
        break;
    case 3:
    //case 4:
        $methodid = rand(1,count($method[$serviceid]));
        break;
    }
    echo "service_id:" . $serviceid . "; method_id:" . $methodid . "\n";
    $service_name=$service[$serviceid];
    $method_name = $method[$serviceid][$methodid];
    echo 'service_name:'. $service_name . ';method_name'.$method_name . '\n';
    $sock = $cli->getsockname();
    $ip = ip2long($sock['host']);
    $port = $sock['port'];
    $seq_no = nova_get_sequence();
    $attach = "{\"key\":\"Hello World\"}";
    $relBuf = '';
    $buf = "Hello Server";
    if (nova_encode($service_name, $method_name, $ip, $port, $seq_no, $attach, $buf, $relBuf)) {
        echo "encode success\n";
        if($cli->send($relBuf)) {
            echo "send success\n";
            $result = $cli->recv();
            if ($result) {
                # code...
                echo "recv success\n";
                if (nova_decode($result, $service_name, $method_name, $ip, $port, $seq_no, $attach, $relBuf)) {
                    # code...
                    echo "service_name: $service_name; method_name:$method_name; ip:$ip; port:$port; seqno:$seq_no; attach:$attach\n";
                }
            } else {
                echo "recv failed\n";
            }
        }
    }
    sleep(1);
}
