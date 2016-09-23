// thrift -out ./src/test/java --gen java:bean demo.thrift

namespace java com.ximalaya.thrift

service TDemoService{

   string ping(),

   string echo(1:string echo),

   map<string, map<string, i64>> multiMap(1:map<string, list<i64>> stringListMap)
}