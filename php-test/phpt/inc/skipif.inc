<?php

if (substr(PHP_OS, 0, 3) == 'WIN') {
	exit("skip for Windows");
}
if (!extension_loaded("swoole") || !function_exists("nova_decode")) {
    exit("zan extension is required");
}