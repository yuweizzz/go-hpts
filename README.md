# go-hpts

将 socks proxy 转换成 http proxy 的工具，主要是为了 npm proxy 可以使用已有的 socks5 代理。

## Get Started

使用方法：

``` bash
# go-hpts
$ cd cmd/go-hpts
$ go build
$ ./go-hpts -h
Usage of ./go-hpts:
  -p string
        http proxy listen port (default "6699")
  -s string
        socks5 server url (default "socks5://127.0.0.1:8888")
  -v    should every proxy request be logged to stdout

# run
$ ./go-hpts -p 6699 -s socks5://username:password@127.0.0.1:8888 -v

# user request
$ curl -x 127.0.0.1:6699 https://registry.npmjs.org/
$ https_proxy=127.0.0.1:6699 curl https://registry.npmjs.org/
```

已有预先搭建的 socks5 服务端只需要替换 `-s` 选项。

如果没有预先搭建的 socks5 服务端，仓库内置了两个用于代码测试的 socks5 服务端，应该可以满足简单的代理场景：

``` bash
# no auth
$ cd socks5_server
$ go build
$ ./socks5_server -h
Usage of ./socks5_server:
  -addr string
    	proxy listen address (default ":8888")
  -v	should every proxy request be logged to stdout

# with auth support
$ cd socks5_server_with_auth_support
$ go build
$ ./socks5_server_with_auth_support -h
Usage of ./socks5_server_with_auth_support:
  -addr string
    	proxy listen address (default ":8888")
  -password string
    	proxy auth password (default "password")
  -username string
    	proxy auth username (default "username")
  -v	should every proxy request be logged to stdout
```

## License

[MIT license](https://github.com/yuweizzz/go-hpts/blob/main/LICENSE)
