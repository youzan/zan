ps aux|grep php |grep -v grep| grep -v xdebug | awk '{print $2}'|sudo xargs kill -9


swoole_server_port::*


unix_socket tcp server + client
unix_socket udp server + client

!!!!!!! 测试所有 带超时的接口

!!!!!!! 测试同步接口
udp server
udp client

清理phpt测试敏感信息
swoole_get_local_ip
