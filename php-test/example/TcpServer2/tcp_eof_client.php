<?php

$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
$client->connect('127.0.0.1', 9506);

//just for test, eof split tcp server...
$client->send("*CMD1|key11=value11_1|key12=value21_2|key13=value31_3$");
$client->send("*CMD1|key11=value12_4|key12=value22_5|key13=value32_6$");

$client->send("*CMD2|key21=value11_7|key22=value21_8|key23=value31_9$");
$client->send("*CMD2|key21=value12_10|key22=value22_11|key23=value32_12$");

$client->send("*CMD3|key31=value11_13|key32=value21_14|key33=value31_15$");
$client->send("*CMD4|key31=value12_16|key32=value22_17|key33=value32_18$");
