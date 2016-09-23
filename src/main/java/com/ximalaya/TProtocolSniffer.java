package com.ximalaya;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoop;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.WriteBufferWaterMark;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.pool.ChannelHealthChecker;
import io.netty.channel.pool.ChannelPoolHandler;
import io.netty.channel.pool.FixedChannelPool;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.concurrent.DefaultPromise;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

import java.io.EOFException;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.thrift.protocol.TMessageType;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.packet.BsdLoopbackPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.NifSelector;

import com.sun.jna.Platform;
import com.ximalaya.codec.TBinary;
import com.ximalaya.codec.TCompact;

/**
 * desc...
 *
 * @author caorong
 */
public class TProtocolSniffer {

  private FixedChannelPool fixedChannelPool = null;
  private String[] repostMethods = null;

  public void setRepostMethods(String[] repostMethods) {
    this.repostMethods = repostMethods;
  }

  // custom with -Dcr.acquireTimeoutMillis=999
  private long acquireTimeoutMillis = Long.parseLong(System.getProperty("cr.acquireTimeoutMillis", "2000"));
  private int maxActive = Integer.parseInt(System.getProperty("cr.maxActive", "3"));
  private int maxClientPendingAcquireSize = Integer
      .parseInt(System.getProperty("cr.maxClientPendingAcquireSize", "100"));
  private int CONNECT_TIMEOUT_MILLIS = Integer
      .parseInt(System.getProperty("cr.CONNECT_TIMEOUT_MILLIS", "3000"));

  // 最大包大小
  private int SNAPLEN = Integer.parseInt(System.getProperty("cr.pcap.snaplen", "65536"));
  private int READ_TIMEOUT = Integer.parseInt(System.getProperty("cr.pcap.READ_TIMEOUT", "1000"));
  //  set os capture buffer size
  private int BUFFER_SIZE = Integer.parseInt(System.getProperty("cr.pcap.BUFFER_SIZE", "1048576"));

  /**
   * copy package to remote machine with netty
   *
   * @param remoteIp
   * @param port
   */
  private void initNettyClient(String remoteIp, int port) throws ExecutionException, InterruptedException {
    if (remoteIp == null || port <= 0) {
      return;
    }
    Bootstrap bootstrap = new Bootstrap();
    Class<? extends SocketChannel> SocketChannel = null;
    EventLoopGroup group = new NioEventLoopGroup(1);

    SocketChannel = NioSocketChannel.class;

    bootstrap.remoteAddress(new InetSocketAddress(remoteIp, port));

    bootstrap.group(group).channel(SocketChannel);
    bootstrap.option(ChannelOption.ALLOCATOR, PooledByteBufAllocator.DEFAULT);
    bootstrap.option(ChannelOption.TCP_NODELAY, true);
    bootstrap.option(ChannelOption.SO_KEEPALIVE, true);
    bootstrap.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, CONNECT_TIMEOUT_MILLIS);
    bootstrap.option(ChannelOption.WRITE_BUFFER_WATER_MARK, new WriteBufferWaterMark(2 * 1024, 8 * 1024));

    fixedChannelPool = new FixedChannelPool(bootstrap, new ChannelPoolHandler() {

      public void channelReleased(Channel ch) throws Exception {
      }

      public void channelAcquired(Channel ch) throws Exception {
      }

      public void channelCreated(Channel ch) throws Exception {
        ch.pipeline().addLast("skiphandler", new SimpleChannelInboundHandler<ByteBuf>() {

          @Override
          protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
          }
        });
      }
    }, new ChannelHealthChecker() {

      public Future<Boolean> isHealthy(Channel channel) {
        EventLoop loop = channel.eventLoop();
        return channel.isOpen() && channel.isActive() && channel.isWritable() ?
            loop.newSucceededFuture(Boolean.TRUE) :
            loop.newSucceededFuture(Boolean.FALSE);
      }
    }, FixedChannelPool.AcquireTimeoutAction.FAIL, acquireTimeoutMillis, maxActive,
        maxClientPendingAcquireSize, false);

    Channel channel = fixedChannelPool.acquire().get();
    fixedChannelPool.release(channel);
  }

  public void init(String fport) throws PcapNativeException, NotOpenException {
    PcapNetworkInterface nif = null;
    List<PcapNetworkInterface> allDevs;
    try {
      nif = new NifSelector().selectNetworkInterface();
      //      allDevs = Pcaps.findAllDevs();
      //      System.out.println("detected netcard, default use first one");
      //      for (PcapNetworkInterface dev : allDevs) {
      //        System.out.println(dev);
      //      }
      //      // first ip
      //      nif = Pcaps.getDevByName(allDevs.get(0).getName());
      //  last localhost
      //      nif = Pcaps.getDevByName(allDevs.get(allDevs.size() - 1).getName());
      // 注意，localhost是 BsdLoopbackPacket
      //      nif = Pcaps.getDevByAddress(InetAddress.getByName("127.0.0.1"));
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }

    System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
    for (PcapAddress addr : nif.getAddresses()) {
      if (addr.getAddress() != null) {
        System.out.println("IP address: " + addr.getAddress());
      }
    }
    System.out.println("");

    PcapHandle.Builder phb = new PcapHandle.Builder(nif.getName()).snaplen(SNAPLEN)
        .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS).timeoutMillis(READ_TIMEOUT)
        .bufferSize(BUFFER_SIZE);
    // TODO check 超大包的情况

    final PcapHandle handle = phb.build();

    //    String filter = "tcp dst port 12121";
    String filter = "";
    if (fport != null) {
      handle.setFilter("tcp dst port " + fport.trim(), BpfProgram.BpfCompileMode.OPTIMIZE);
      System.out.println("set filter => " + "tcp dst port " + fport.trim());
    } else {
      handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
    }

    Runtime.getRuntime().addShutdownHook(new Thread() {
      @Override
      public void run() {
        System.out.println("waiting for stop complete!");
        PcapStat ps = null;
        try {
          ps = handle.getStats();
        } catch (PcapNativeException e) {
        } catch (NotOpenException e) {
        }
        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
        if (Platform.isWindows()) {
          System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
        }

        handle.close();
      }
    });

    while (true) {
      Packet packet = null;
      try {
        packet = handle.getNextPacketEx();
        if (packet instanceof EthernetPacket || packet instanceof BsdLoopbackPacket) {
          //        System.out.println(handle.getTimestamp());
          //        System.out.println(packet);
          if (packet.getPayload() instanceof IpV4Packet) {
            IpV4Packet ipV4Packet = (IpV4Packet) packet.getPayload();
            IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
            Inet4Address srcAddr = ipV4Header.getSrcAddr();
            Inet4Address dstAddr = ipV4Header.getDstAddr();

            if (ipV4Packet.getPayload() instanceof TcpPacket) {
              TcpPacket tcpPacket = (TcpPacket) ipV4Packet.getPayload();
              TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
              TcpPort srcPort = tcpHeader.getSrcPort();
              TcpPort dstPort = tcpHeader.getDstPort();
              //   System.out.println(srcPort + " - " + dstPort);
              //   System.out.println(srcPort.valueAsString() + " - " + dstPort.valueAsString());

              // 有业务data
              if (tcpPacket.getPayload() != null && tcpPacket.getPayload().length() > 0) {
                ByteBuf byteBuf = PooledByteBufAllocator.DEFAULT.heapBuffer()
                    .writeBytes(tcpPacket.getPayload().getRawData());
                //                System.out.println(tcpHeader);
                //                System.out.println(ByteBufUtil.prettyHexDump(byteBuf));
                handleData(srcAddr, srcPort, dstAddr, dstPort, byteBuf);
              }
            }
          }
        }
      } catch (EOFException e) {
        e.printStackTrace();
      } catch (TimeoutException e) {
      }
    }
  }

  private void handleData(Inet4Address srcAddr, TcpPort srcPort, Inet4Address dstAddr, TcpPort dstPort,
      ByteBuf byteBuf) {
    // 猜测协议
    try {
      // 判断frame
      int datalen = byteBuf.writerIndex();
      if (datalen > 4) {
        int frameSize = byteBuf.readInt();
        // framed thrift protocol
        if (datalen == frameSize + 4) {
          //  System.out.println(datalen + " - " + frameSize);
          ThriftCodecUtils.MessageType messageType = ThriftCodecUtils.isMainstayProtocol(byteBuf);
          // 读完magic后, 回退 buf
          byteBuf.readerIndex(byteBuf.readerIndex() - 2);
          Tuple.Tuple2<String, Byte> methodNameType = null;
          String messageVerStr = null;
          switch (messageType) {
            case originCompactThrift:
              messageVerStr = "M2-C";
              // 解析thrift协议头
              methodNameType = TCompact.readCompactMessageBegin(byteBuf);
              break;
            case originBinaryThrift:
              messageVerStr = "M2-B";
              methodNameType = TBinary.readBinaryMessageBegin(byteBuf);
          }
          if (methodNameType != null) {
            String tMessageTypeStr = null;
            if (methodNameType._2() == TMessageType.CALL) {
              tMessageTypeStr = "req";
            } else if (methodNameType._2() == TMessageType.REPLY) {
              tMessageTypeStr = "resp";
            } else if (methodNameType._2() == TMessageType.EXCEPTION) {
              tMessageTypeStr = "resp exception";
            } else {
              tMessageTypeStr = "oneway";
            }

            System.out.printf("req[%s] from %s:%s to %s:%s %s %s\n", messageVerStr, srcAddr,
                srcPort.valueAsString(), dstAddr, dstPort.valueAsString(), tMessageTypeStr,
                methodNameType._1());
            // 仅转发请求
            if (methodNameType._2() == TMessageType.CALL) {
              sendPackageAsync(byteBuf.resetReaderIndex(), methodNameType._1());
            }
          }
        }
      }
    } catch (Exception e) {
      // skip
      // e.printStackTrace();
    }
  }

  private boolean matchMethod(String methodName) {
    for (String method : repostMethods) {
      if (method.equals(methodName)) {
        return true;
      }
    }
    return false;
  }

  private void sendPackageAsync(final ByteBuf byteBuf, String methodName) {
    if (fixedChannelPool != null) {
      // if filter method?
      if (repostMethods != null && !matchMethod(methodName)) {
        return;
      }
      fixedChannelPool.acquire().addListener(new GenericFutureListener<DefaultPromise<? super Channel>>() {
        public void operationComplete(DefaultPromise<? super Channel> future) throws Exception {
          if (future.isSuccess()) {
            Channel channel = null;
            try {
              channel = ((Channel) future.get());
              ChannelFuture writeMsgFuture = channel.writeAndFlush(byteBuf);
              writeMsgFuture.addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture future) throws Exception {
                  if (!future.isSuccess()) {
                    System.err.println("write data error, maybe you should check repost server log!");
                  }
                }
              });
            } catch (Exception e) {
              e.printStackTrace();
            } finally {
              if (channel != null) {
                fixedChannelPool.release(channel);
              }
            }

          } else {
            System.err.println("acquire channel error! maybe you should increase cr.maxActive !");
          }
        }
      });
    }
  }

  public static void main(String[] args) throws PcapNativeException, NotOpenException, ParseException {
    Options options = new Options();

    // add t option
    Option fportOpt = Option.builder("fport").hasArg().numberOfArgs(1).required(false).type(int.class)
        .argName("port").desc(" only catch packet with specified port").build();
    Option toOpt = Option.builder("to").hasArg().numberOfArgs(1).required(false).type(String.class)
        .argName("ip:port").desc(" send packet to specified thrift server ip:port, e.g 192.168.3.2:10101")
        .build();
    Option methodsOpt = Option.builder("methods").hasArg().numberOfArgs(1).numberOfArgs(1).required(false)
        .type(String.class).argName("methodName").desc(" methods matched to send, split with ',' ").build();
    Option helpOpt = new Option("h", "print this message");

    options.addOption(fportOpt);
    options.addOption(toOpt);
    options.addOption(methodsOpt);
    options.addOption(helpOpt);

    CommandLineParser parser = new DefaultParser();
    CommandLine cmd = null;
    try {
      cmd = parser.parse(options, args);
    } catch (Exception e) {
      e.printStackTrace();
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("thriftcopy", options);
      System.exit(-1);
    }

    if (cmd.getOptionValue("h", "false").equals("true")) {
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("thriftcopy", options);
      System.exit(0);
    }
    if (cmd.getOptionValue("to") == null) {
      System.out.println("run thriftcopy as sniffer mode!");
    }

    //  System.out.println(cmd.getOptionValue("fport"));
    //  System.out.println(cmd.getOptionValue("to"));
    //  System.out.println(cmd.getOptionValue("methods"));
    String to = cmd.getOptionValue("to");
    String methods = cmd.getOptionValue("methods");
    String fport = cmd.getOptionValue("fport");

    TProtocolSniffer tProtocolSniffer = new TProtocolSniffer();
    if (to != null) {
      try {
        String[] ipport = to.split(":");
        tProtocolSniffer.initNettyClient(ipport[0], Integer.parseInt(ipport[1]));
        if (methods != null) {
          tProtocolSniffer.setRepostMethods(methods.split(","));
        }

      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    System.out.printf(
        "ready to repost local thrift request with port [%s] with methods match [%s] from local machine to remote mathine [%s]\n",
        fport, methods, to);

    tProtocolSniffer.init(fport);
  }
}
