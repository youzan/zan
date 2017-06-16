<?php

require __DIR__ . "/../vendor/autoload.php";
error_reporting(E_ALL);

define("NOVA_HOST", "127.0.0.1");
define("NOVA_PORT", 8060);


// 2m data |> client -> server -> mysql
// server 的 worker进程 内存暴涨

class Exception_Db_ResultError extends Exception {}
class Exception_System extends Exception {}
class Config {
    public static function get($key) {
        $conf = [
            "is_admin" => false,
            "attachment" => [
                "request_ip" => "0.0.0.0",
                "kdt_id" => 42,
                "admin_id" => 41,
                "client_id" => "client_id_42",
                "other_atta" => ["t"=>time()],
                "CAT_TRACE" => [],
            ],
            "nova.client" => [
                'host' => NOVA_HOST,
                'port' => NOVA_PORT,
                'timeout' => 60000,
                'persistent' => false
            ],
            "nova.swoole.client" => [
                'open_length_check' => 1,
                'package_length_type' => 'N',
                'package_length_offset' => 0,
                'package_body_offset' => 0,
                'open_nova_protocol' => 1
            ],
            "nova_routes.statics" => []
        ];
        if (isset($conf[$key])) {
            return $conf[$key];
        }

        throw new RuntimeException();
    }
}


// nc -k -l 9999
// while true;  do nc -4 -l 8080 > /dev/null; done


//for ($i = 0; $i < 10; $i++) {
//    if (pcntl_fork() === 0) {
//        while (true) {
//            testInsert();
//            testSelect();
//        }
//        exit;
//    }
//}

while (true) {
    testInsert();
    testSelect();
}

function testInsert()
{
    $featureServ = new \Com\Youzan\Showcase\Feature\Service\FeatureService();

    $feature = new \Com\Youzan\Showcase\Feature\Entity\InputFeature();
    $feature->kdtId = 18059894;
    $feature->id = null;
    $feature->title = "test_core";
    $feature->templateId = null;
    $feature->components = '[{"a":"' . str_repeat("x", 1024 * 1024 * 1.9) . '"}]';
    $feature->isDisplay = false;
    $feature->platform = null;
    $feature->categoryIdArr = [];

    try {
        $result = $featureServ->createFeature($feature);
    } catch (\Exception $ex) {
        echo $ex;
    }
}

function testSelect()
{
    $featureServ = new \Com\Youzan\Showcase\Feature\Service\FeatureService();

    $kdtId = 18059894;
    $isDisplay = 1;
    $curPage = 1;
    $pageSize = 999999999;
    $keyword = '';
    $sortField = '';
    $sortDirection = '';

    try {
        $list = $featureServ->findFeatureListByKdtId($kdtId, $isDisplay, $curPage, $pageSize, $keyword, $sortField, $sortDirection);
        if (count($list) < 115) {
            echo "error\n";
        }
    } catch (\Exception $ex) {
        echo $ex;
    }
}