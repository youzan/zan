<?php

require_once __DIR__ . "/../../Bootstrap.php";


//$file = __DIR__ . "/tmp.file";
// 最大 限制1024M
// user set data buffer must between 0~1048576
//$data = file_get_contents("/dev/urandom", null, null, null, 1024 * 1024 + 1);
//swoole_async_write($file, $data, -1, function($f, $l) {
//    var_dump($l);
//});
//@unlink($file);


/*
$recursiveWrite = function($dep = 0) use($data, &$recursiveWrite, $file, $size) {
    swoole_async_write($file, $data, -1, function ($file, $len) use(&$recursiveWrite, $dep, $size) {
        if ($dep > 100) {
            echo "SUCCESS";
            unlink($file);
            return false;
        }

        assert($len === $size);
        $recursiveWrite(++$dep);
        return true;
    });
};
*/
// $recursiveWrite();

function recursiveWrite($dep = 0, $size = 1024 * 1024)
{
    static $data;
    if ($data === null) {
        $data = file_get_contents("/dev/urandom", null, null, null, $size);
    }

    $file = "tmp.file";

    swoole_async_write($file, $data, -1, function ($file, $len) use(&$recursiveWrite, $dep, $size) {
        if ($dep > 100) {
            echo "SUCCESS";
            unlink($file);
            return false;
        }

        assert($len === $size);
        recursiveWrite(++$dep);
        return true;
    });
}

