
# thriftcopy

选择本地网卡，通过底层 libpcap 抓包，过滤出所有本地 发出 和 收到的 thrift 请求，并将指定方法的请求包转发到指定远程机器。


```
req[M2] from /192.168.3.56:56626 to /192.168.3.132:9181 req thrifxxxxxxxxxxery:fixdmIds
req[M2] from /192.168.3.132:9181 to /192.168.3.56:56626 resp findxxxxxxxxxxAlbumIxs
req[M2] from /192.168.3.56:36819 to /192.168.3.132:10021 req thrixxxxxxxxxxoductqxery:findMexxxxxxxxxxxxxxxxxxIds
req[M2] from /192.168.3.132:10021 to /192.168.3.56:36819 resp finxxxxxxxxxxductByxwnerIds
req[M2] from /192.168.3.132:42588 to /192.168.3.131:9201 req querxxxxxxxxxxadioStxtus
```

注:

带 `:` 为multiplex


usege:

```
java -jar pcaptest-0.1.0-jar-with-dependencies.jar [ip_torepost] [port_torepost] [methodName...]

or

java -jar pcaptest-0.1.0-jar-with-dependencies.jar // just a thrift protocol sniffer
```

## feature and limit

1. only support framed transport
2. do not support `oneway` type



