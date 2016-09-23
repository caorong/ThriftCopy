package com.ximalaya.handler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.thrift.TException;

import com.ximalaya.thrift.TDemoService;

/**
 * desc...
 *
 * @author caorong
 */
public class DemoServiceHandler implements TDemoService.Iface {
  private AtomicInteger count;

  public DemoServiceHandler(AtomicInteger count) {
    this.count = count;
  }

  public String ping() throws TException {
    System.out.println(count.incrementAndGet());
    return "pong";
  }

  public String echo(String echo) throws TException {
    count.incrementAndGet();
    return echo;
  }

  private final Random random = new Random();

  public Map<String, Map<String, Long>> multiMap(Map<String, List<Long>> stringListMap) throws TException {
    count.incrementAndGet();
    HashMap<String, Map<String, Long>> maps = new HashMap<String, Map<String, Long>>();
    HashMap<String, Long> subMaps = new HashMap<String, Long>();
    subMaps.put("test", random.nextLong());
    maps.put("test", subMaps);
    return maps;
  }
}
