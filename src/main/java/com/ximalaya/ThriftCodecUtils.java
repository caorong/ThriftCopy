package com.ximalaya;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;

import java.util.Arrays;

/**
 * desc...
 *
 * @author caorong
 */
public class ThriftCodecUtils {

  public enum MessageType {originCompactThrift, originBinaryThrift, unknown}

  public static final byte[] ORIGIN_COMPACT_THRIFT_MAGIC = new byte[] { (byte) 0x82, (byte) 0x21 };
  public static final byte[] ORIGIN_BINARY_THRIFT_MAGIC = new byte[] { (byte) 0x80, (byte) 0x01 };

  /**
   * read head 2 byte to decided which type / protocol
   *
   * @param in bytebyf (read idx will increase 2)
   * @return type
   */
  public static final MessageType isMainstayProtocol(ByteBuf in) {
    MessageType messageType;
    final byte[] magic = new byte[2];
    in.readBytes(magic);
    if (ORIGIN_COMPACT_THRIFT_MAGIC[0] == magic[0]) {
      messageType = MessageType.originCompactThrift;
    } else if (ORIGIN_BINARY_THRIFT_MAGIC[0] == magic[0] && ORIGIN_BINARY_THRIFT_MAGIC[1] == magic[1]) {
      messageType = MessageType.originBinaryThrift;
    } else {
      throw new IllegalArgumentException("bad magic " + ByteBufUtil.hexDump(magic));
    }
    return messageType;
  }
}
