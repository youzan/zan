--TEST--
swoole_http_client: contruct_fail_core

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";

try {
    $httpClient = new \swoole_http_client(null, null);
    $httpClient->execute("/", function(\swoole_http_client $httpClient) {});
    echo "SUCCESS";
} catch (\Exception $ex) {
    echo "EXCEPTION";
}
?>

--EXPECT--
EXCEPTION