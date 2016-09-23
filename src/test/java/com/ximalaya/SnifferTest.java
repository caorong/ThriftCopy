package com.ximalaya;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.cli.ParseException;
import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TCompactProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.server.TServer;
import org.apache.thrift.server.TThreadedSelectorServer;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TNonblockingServerSocket;
import org.apache.thrift.transport.TNonblockingServerTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.junit.Test;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import com.ximalaya.codec.TBinary;
import com.ximalaya.handler.DemoServiceHandler;
import com.ximalaya.thrift.TDemoService;

/**
 * desc...
 *
 * @author caorong
 */
public class SnifferTest {

  final Map<Integer, AtomicInteger> counter = new HashMap<Integer, AtomicInteger>();

  public void createThriftServer(final int port) {
    new Thread(new Runnable() {
      public void run() {
        counter.put(port, new AtomicInteger(0));
        DemoServiceHandler demoServiceHandler = new DemoServiceHandler(counter.get(port));
        TNonblockingServerTransport tServerTransport = null;
        try {
          tServerTransport = new TNonblockingServerSocket(port, 1000);
        } catch (TTransportException e) {
          e.printStackTrace();
          System.exit(-1);
        }
        TThreadedSelectorServer.Args targs = new TThreadedSelectorServer.Args(tServerTransport);
        //        targs.protocolFactory(new TCompactProtocol.Factory());
        targs.protocolFactory(new TBinaryProtocol.Factory());
        targs.transportFactory(new TFramedTransport.Factory());
        targs.processor(new TDemoService.Processor(demoServiceHandler));

        TServer server = new TThreadedSelectorServer(targs);

        server.serve();
      }
    }).start();
    try {
      Thread.sleep(500);
    } catch (InterruptedException e) {
    }
  }

  public TDemoService.Client createThriftClient(Class<? extends TProtocol> protocolCls, int port)
      throws TException, NoSuchMethodException, IllegalAccessException, InvocationTargetException,
      InstantiationException {
    TSocket tSocket = new TSocket("localhost", port);
    TTransport tTransport = new TFramedTransport(tSocket);
    tTransport.open();

    TDemoService.Client.Factory factory = new TDemoService.Client.Factory();
    //    TDemoService.Client client = factory.getClient(new TCompactProtocol(tTransport));
    TDemoService.Client client = factory
        .getClient(protocolCls.getConstructor(TTransport.class).newInstance(tTransport));
    return client;
  }

  @Test
  public void testRunServer()
      throws TException, InterruptedException, InvocationTargetException, NoSuchMethodException,
      InstantiationException, IllegalAccessException {
    createThriftServer(10099);
    TDemoService.Client client = createThriftClient(TBinaryProtocol.class, 10099);
    System.out.println(client.ping());
    Thread.sleep(1000 * 10000);
  }

  @Test
  public void send()
      throws TException, InvocationTargetException, NoSuchMethodException, InstantiationException,
      IllegalAccessException {
    TDemoService.Client client = createThriftClient(TBinaryProtocol.class, 10099);
    System.out.println(client.ping());
  }

  @Test
  public void testRunServer2()
      throws TException, InterruptedException, InvocationTargetException, NoSuchMethodException,
      InstantiationException, IllegalAccessException {
    createThriftServer(11000);

    TDemoService.Client client = createThriftClient(TBinaryProtocol.class, 11000);
    System.out.println(client.ping());
    Thread.sleep(1000 * 10000);
  }

  @Test
  public void test() throws TException, PcapNativeException, ParseException, NotOpenException {
    //    createThriftServer(10099);
    //    createThriftServer(11999);
    //    TDemoService.Client client = createThriftClient(10999);
    //    client.ping();

    TProtocolSniffer tProtocolSniffer = new TProtocolSniffer();
    //localhost 10999 //    -fport 10099 -to localhost:11000
    TProtocolSniffer.main(new String[] { "-fport", "10099", "-to", "localhost:11000" });
  }

}
