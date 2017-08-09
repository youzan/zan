<p>
<a href="https://github.com/youzan/"><img alt="有赞logo" width="36px" src="https://img.yzcdn.cn/public_files/2017/02/09/e84aa8cbbf7852688c86218c1f3bbf17.png" alt="youzan">
</p></a>
<p align="center">
    <img src="https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small@2x.png?raw=true" alt="zanphp logo" srcset="https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small.png?raw=true 1x, https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small@2x.png?raw=true 2x, https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small.png?raw=true" width="210" height="210">
</p>
<p align="center">高效稳定、安全易用、线上实时验证的全异步高性能网络库，通过PHP扩展方式提供。</p>
<p align="center">遵循Apache协议，基于Swoole 1.8.5版本分支重构研发。</p>
</p>
<p align="center">在此特别鸣谢Swoole开发组为PHP开源社区付出的努力和汗水。</p>

[![License](https://img.shields.io/badge/license-apache2-blue.svg)](LICENSE)
[![Build Status](https://api.travis-ci.org/youzan/zan.svg)](https://travis-ci.org/youzan/zan)


## Zan做了哪些事儿
1.  大量模块解耦拆分
2.  修复大量Bug、逻辑缺陷(内存泄露、释放逻辑)
3.  内置通用连接池
4.  支持时间轮算法
5.  异步接口支持超时
6.  增强Mysql client安全性(预处理、事务)
7.  Nova协议支持(RPC协议)
8.  支持平滑重启
9.  接口单元测试覆盖率100%
10. 实时、全面的API文档
11. ...



## 编译安装步骤
```
git clone https://github.com/youzan/zan.git
cd zan-extension
phpize
./configure
make 
make install
```

## 建议安装配置项
```
phpize 
./configure --enable-openssl
make 
make install
```

## Zan编译安装常见问题
1.  使用async-redis客户端及依赖sockets扩展默认打开，使用ssl功能默认不打开。
    1. 若不想使用async-redis客户端，可在configure时采用选项```--disable-async-redis```关闭。
    2. 使用async-redis客户端需要安装hiredis库，当前默认已提供x86下linux/mac的hiredis库。若需要支持arm等硬件平台，需要先安装hiredis库，然后在config.m4文件中添加```PHP_ADD_LIBRARY(hiredis, 1, ZAN_SHARED_LIBADD)```将其编译进ZAN扩展。
    3. 若想使用ssl功能，可在configure时采用选项```--enable-openssl```开启。
2.  若执行phpize报xxx/sed: No such file，请重装php或将/usr/bin/sed拷贝到xxx目录下。
3.  若执行phpize报Cannot find autoconf，请先安装autoconf工具。
4.  若执行configure时报错libcurl not installed，请重新安转curl库，并保证库与头文件名称与路径正确。
    1. 如库名称与路径/usr/lib/libcurl.so(通常带版本号的libxxx.so.xxx会软连接到libXXX.so供链接器识别)，对应头文件路径则为/usr/include/curl。
    2. 确认curl库正确安装后，请务必重新phpize && configure以保证新的配置生效。
    3. 若按1)、2)操作后仍然报错，则可修改config.m4中PHP_CURL的配置路径为你安装curl的路径。
5.  若执行configure时报错enable sockets support, sockets extension installed incorrectly，请确认PHP版本及sockets扩展正确安装。
    1. PHP版本需要在5.6以上版本。
    2. 在PHP的include路径下应该包含头文件ext/sockets/php_sockets.h。
    3. sockets扩展在zan之前加载(php.ini中的引入加载顺序)，以确保能引用符号表信息。
6.  若执行configure时报错Enable openssl support, require openssl library，请重新安装openssl库并保证能链接正确。
    1. 重新安装openssl库。
    2. 添加openssl库路径供链接器找lib，如将```-L/usr/local/opt/openssl/lib```补充到config.m4中的LDFLAGS。
    3. 添加openssl库依赖头文件路径，如将```-I/usr/local/opt/openssl/include```添加到config.m4中的CPPFLAGS。
    4. 依然需要重新配置，按编译扩展步骤安装，见上方。

## 官方交流渠道
官网：[点我进入](http://zanphp.io)

Zan 的文档仓库地址：[zan-doc](https://github.com/youzan/zan-doc/)

在线查看文档：[http://zandoc.zanphp.io ✈](http://zandoc.zanphp.io)

QQ群：115728122


## 常用链接
- [异步网络模型](http://tech.youzan.com/yi-bu-wang-luo-mo-xing/)
- [PHP异步编程: 手把手教你实现co与Koa](https://github.com/youzan/php-co-koa) 
- [深入理解PHP opcode优化](http://tech.youzan.com/understanding-opcode-optimization-in-php/) 
- [Zan-Stats监控工具](https://github.com/imaben/zan-stats) 


## 捐赠我们
[捐赠通道](http://zanphp.io/donate)

## License

[Zan 框架](https://github.com/youzan/zan)基于 [Apache2.0 license](http://www.apache.org/licenses/LICENSE-2.0) 进行开源。

