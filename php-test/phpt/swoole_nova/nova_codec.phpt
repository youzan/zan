--TEST--
nova_codec
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../../Bootstrap.php";


function testNovaCodec($attachLen, $len)
{
    $service = "\0service" . RandStr::gen(10, RandStr::ALL);
    $method = "\0method" . RandStr::gen(10, RandStr::ALL);

    $ip = ip2long("127.0.0.1");
    $port = rand(1, 65535);
    $seq = rand(1, 999999999);

    $attach = RandStr::gen($attachLen - 3000, RandStr::ALL);
    $data = RandStr::gen($len, RandStr::ALL);


    $encodedString = "";
    if (!nova_encode($service, $method, $ip, $port, $seq, $attach, $data, $encodedString)) {
        echo strlen($attach), "\n";
        echo "encode fail";
    }
    $_service = $_method = $_ip = $_port = $_seq = $_attach = $_data = null;
    if (!nova_decode($encodedString, $_service, $_method, $_ip, $_port, $_seq, $_attach, $_data)) {
        echo "decode fail";
    }

    assert($service === $_service);
    assert($method === $_method);
    assert($ip === $_ip);
    assert($port === $_port);
    assert($seq === $_seq);
    assert($attach === $_attach);
    assert($data === $_data);

}

testNovaCodec(10000, 1024 * 1024);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS
