<?php

//p (zval *)client->response->result_array->value->ht->pListTail->pDataPtr

function bug()
{
    for ($i = 0; $i < 10; $i++) {
        echo "n$i\n";

        $link = new \mysqli();
        $link->connect("127.0.0.1", "root", "", "information_schema", 3306);
        $sql = "select 1";
        $ret = swoole_mysql_query($link, $sql, function($link, $result) {
            echo count($result), "\n";
        });
        assert($ret === true);
    }
}


bug();
//test1();
//test2();



function test1()
{
    $links = [];
    for ($i = 0; $i < 10; $i++) {
        $link = new \mysqli();
        $link->connect("127.0.0.1", "root", "", "information_schema", 3306);
        $links[] = $link;
    }
    foreach ($links as $link) {
        $sql = "select 1";
        $ret = swoole_mysql_query($link, $sql, function($link, $result) {
            echo count($result), "\n";
        });
        assert($ret === true);
    }
}



class MysqlTest
{
    private $link;
    public function __construct()
    {
        $this->link = new \mysqli();
        $this->link->connect("127.0.0.1", "root", "", "information_schema", 3306);
    }

    public function sql($sql)
    {
        $ret = swoole_mysql_query($this->link, $sql, function($link, $result) {
            echo count($result), "\n";
        });
        assert($ret === true);
    }
}


function test2()
{
    for ($i = 0; $i < 10; $i++) {
        echo "n$i\n";

        $mysql = new MysqlTest();
        $sql = <<<SQL
SELECT  `id`,`kdt_id`,`title`,`alias`,`type`,`template_id`,`goods_num`,`num`,`is_display`,`created_time`, 
`update_time`,`is_delete`,`is_lock`,`platform`,`components` FROM `feature_v2` WHERE kdt_id=18059894
and `id` = 45482696
SQL;
        $sql = "select 1";
        $mysql->sql($sql);
    }
}

