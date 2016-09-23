package com.ximalaya.codec;

import io.netty.buffer.ByteBuf;

import java.io.UnsupportedEncodingException;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TProtocolException;

import com.ximalaya.Tuple;

/**
 * @author caorong
 */
public class TCompact {
  private static final byte PROTOCOL_ID = (byte) 0x82;
  private static final byte VERSION = 1;
  private static final byte VERSION_MASK = 0x1f; // 0001 1111
  private static final int TYPE_SHIFT_AMOUNT = 5;
  private static final byte TYPE_BITS = 0x07; // 0000 0111

  public static Tuple.Tuple2<String, Byte> readCompactMessageBegin(ByteBuf byteBuf)
      throws TException, UnsupportedEncodingException {
    byte protocolId = byteBuf.readByte();
    if (protocolId != PROTOCOL_ID) {
      throw new TProtocolException(
          "Expected protocol id " + Integer.toHexString(PROTOCOL_ID) + " but got " + Integer
              .toHexString(protocolId) + ", may be choosed wrong protocol?");
    }
    byte versionAndType = byteBuf.readByte();
    byte version = (byte) (versionAndType & VERSION_MASK);
    if (version != VERSION) {
      throw new TProtocolException("Expected version " + VERSION + " but got " + version);
    }
    byte type = (byte) ((versionAndType >> TYPE_SHIFT_AMOUNT) & TYPE_BITS);
    int seqid = readVarint32(byteBuf);
    String methodName = readString(byteBuf);
    return Tuple.tuple(methodName, type);
  }

  private static String readString(ByteBuf byteBuf) throws TException, UnsupportedEncodingException {
    int length = readVarint32(byteBuf);
    //    System.out.println("readString:" + length);
    if (length < byteBuf.readableBytes() && length >= 0) {
      if (length == 0) {
        return "";
      } else {
        byte[] strbyte = new byte[length];
        byteBuf.readBytes(strbyte);
        return new String(strbyte, "UTF-8");
      }
    } else {
      throw new RuntimeException("readString length=[" + length + "] is invalid!");
    }
  }

  private static int readVarint32(ByteBuf byteBuf) throws TException {
    int result = 0;
    int shift = 0;
    if (byteBuf.readableBytes() >= 5) {
      //      byte[] buf = trans_.getBuffer();
      //      int pos = trans_.getBufferPosition();
      int off = 0;
      while (true) {
        byte b = byteBuf.readByte();
        //        byte b = buf[pos + off];
        result |= (int) (b & 0x7f) << shift;
        if ((b & 0x80) != 0x80)
          break;
        shift += 7;
        off++;
      }
      //      trans_.consumeBuffer(off + 1);
    } else {
      while (true) {
        byte b = byteBuf.readByte(); //readByte();
        result |= (int) (b & 0x7f) << shift;
        if ((b & 0x80) != 0x80)
          break;
        shift += 7;
      }
    }
    return result;
  }
}
