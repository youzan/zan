<?php


//function nova_decode($buf, &$service_name, &$method_name, &$ip, &$port, &$seq_no, &$attach, &$data) {}
//function nova_encode($service_name, $method_name, $ip, $port, $seq_no, $attach, $data, &$buf) {}


require_once __DIR__ . "/../../Bootstrap.php";


function testNovaCodec($len)
{
    $service = "\0service" . RandStr::gen(1024, RandStr::ALL);
    $method = "\0method" . RandStr::gen(1024, RandStr::ALL);

    $ip = ip2long("127.0.0.1");
    $port = rand(1, 65535);
    $seq = rand(1, 999999999);

    $attach = RandStr::gen($len, RandStr::ALL);
    $data = RandStr::gen($len, RandStr::ALL);

    $encodedString = "";
    assert(true === nova_encode($service, $method, $ip, $port, $seq, $attach, $data, $encodedString));

    $_service = $_method = $_ip = $_port = $_seq = $_attach = $_data = null;
    assert(true === nova_decode($encodedString, $_service, $_method, $_ip, $_port, $_seq, $_attach, $_data));

    assert($service === $_service);
    assert($method === $_method);
    assert($ip === $_ip);
    assert($port === $_port);
    assert($seq === $_seq);
    assert($attach === $_attach);
    assert($data === $_data);

}

for($i = 0; $i < 1024; $i++) {
    testNovaCodec(1024 * 1024);
}
