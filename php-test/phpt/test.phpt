--TEST--
swoole test
--SKIPIF--
<?php 
if (!extension_loaded("swoole")) {
    echo "skip";
}
if (!function_exists("nova_decode")) {
	echo "need yz-swoole extension";
}
?>
--INI--

--FILE--
<?php 
echo "yz-swoole extension is available";
?>
--EXPECT--
yz-swoole extension is available