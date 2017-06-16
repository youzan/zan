<?php
ini_set("memory_limit", "1024m");


//2865
//507749
//794279
//908349
//1727449
//15157478
//16153725
//18059894

// source /data/users/chuxiaofeng/.gdbinit
// f 2
// p (zval *)client->response->result_array->value->ht->pListHead->pDataPtr
// printzv $1

//18059894
function bug($sql, $dep = 0)
{
    static $addRef = [];

    if ($dep > 2) {
        return;
    }

    $link = new \mysqli();
    $link->connect("127.0.0.1", "user_fans", "", "test", 3306);
    $addRef[] = $link;

    $ret = swoole_mysql_query($link, $sql, function($link, $result) use($sql, $dep) {
        echo count($result), "\n";
        bug($sql, ++$dep);
    });

    assert($ret === true);
}


function test($sql, $depth = 0)
{
    if ($depth > 2) {
        return;

    }
    $db = new \swoole_mysql;
    $server = [
        'host'     => '127.0.0.1',
        'port'     => '3306',
        'user'     => 'root',
        'password' => '',
        'database' => 'test',
    ];

    $db->connect($server, function ($db, $r) use($sql, $depth) {
        if ($r === false) {
            var_dump($db->connect_errno, $db->connect_error);
            exit();
        }
        $db->query($sql, function (\swoole_mysql $db, $r) use($sql, $depth) {
            if ($r === false) {
                return var_dump($db->error, $db->errno);
            } elseif ($r === true) {
                echo count($r), "\n";
                // var_dump($db->affected_rows, $db->insert_id);
            } else {
                // var_dump($r);
            }
            test($sql, ++$depth);
        });
    });
}


$sql = <<<SQL
SELECT  `id`,`kdt_id`,`title`,`alias`,`type`,`template_id`,`goods_num`,`num`,`is_display`,`created_time`,
`update_time`,`is_delete`,`is_lock`,`platform`,`components` FROM `feature_v2` WHERE kdt_id=18059894
SQL;


//fix($sql);

test($sql);

