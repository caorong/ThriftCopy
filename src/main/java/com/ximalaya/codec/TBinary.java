package com.ximalaya.codec;

import io.netty.buffer.ByteBuf;

import java.nio.charset.Charset;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TProtocolException;

import com.ximalaya.Tuple;

/**
 * desc...
 *
 * @author caorong
 */
public class TBinary {
  private final static Charset utf8charset = Charset.forName("UTF-8");

  public static Tuple.Tuple2<String, Byte> readBinaryMessageBegin(ByteBuf byteBuf) throws TException {
    int size = byteBuf.readInt();
    if (size < 0) {
      int version = size & -65536;
      if (version != -2147418112) {
        throw new TProtocolException(4, "Bad version in readMessageBegin");
      } else {
        return Tuple.tuple(readString(byteBuf), (byte) (size & 255));
      }
    } else {
      // old version binary protocol
      return Tuple.tuple(readStringBody(byteBuf, size), byteBuf.readByte());
    }
  }

  private static String readStringBody(ByteBuf byteBuf, int size) throws TException {
    return (String) byteBuf.readCharSequence(size, utf8charset);
  }

  private static String readString(ByteBuf byteBuf) throws TException {
    int size = byteBuf.readInt();
    if (size < 0 || size > 200) {
      throw new TProtocolException(4, "Bad message length=" + size);
    }
    return readStringBody(byteBuf, size);
  }

}
