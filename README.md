<p>
<a href="https://github.com/youzan/"><img alt="有赞logo" width="36px" src="https://img.yzcdn.cn/public_files/2017/02/09/e84aa8cbbf7852688c86218c1f3bbf17.png" alt="youzan">
</p></a>
<p align="center">
    <img src="https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small@2x.png?raw=true" alt="zanphp logo" srcset="https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small.png?raw=true 1x, https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small@2x.png?raw=true 2x, https://github.com/youzan/zanphp.io/blob/master/src/img/zan-logo-small.png?raw=true" width="210" height="210">
</p>
[![License](https://img.shields.io/badge/license-apache2-blue.svg)](LICENSE)
</p>
<p align="center">高效稳定、安全易用、线上实时验证的全异步高性能网络库，通过PHP扩展方式提供。</p>
<p align="center">遵循Apache协议，基于Swoole 1.8.5版本分支重构研发。</p>
</p>
<p align="center">在此特别鸣谢Swoole开发组为PHP开源社区付出的努力和汗水。</p>


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
./configure --enable-sockets --enable-async-redis  --enable-openssl
make 
make install
```

## 官方交流渠道
官网：[点我进入](http://zanphp.io)

Zan 的文档仓库地址：[zan-doc](https://github.com/youzan/zan-doc/)

在线查看文档：[http://zandoc.zanphp.io ✈](http://zandoc.zanphp.io)

QQ群：115728122


## 常用链接
- [异步网络模型](http://tech.youzan.com/yi-bu-wang-luo-mo-xing/)
- [PHP异步编程: 手把手教你实现co与Koa](https://github.com/youzan/php-co-koa) 
- [深入理解PHP opcode优化](http://tech.youzan.com/understanding-opcode-optimization-in-php/) 


## 捐赠我们
[捐赠通道](http://zanphp.io/donate)

## License

[Zan 框架](https://github.com/youzan/zan)基于 [Apache2.0 license](http://www.apache.org/licenses/LICENSE-2.0) 进行开源。

