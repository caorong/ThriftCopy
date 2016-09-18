package com.ximalaya;

import java.io.Serializable;

/**
 * desc...
 *
 * @author caorong
 */
public abstract class Tuple implements Serializable {

  /**
   *
   */
  private static final long serialVersionUID = 1864976957848837540L;

  public static <A, B> Tuple2<A, B> tuple(A a, B b) {
    return new Tuple2<A, B>(a, b);
  }

  public static <A, B, C> Tuple3<A, B, C> tuple(A a, B b, C c) {
    return new Tuple3<A, B, C>(a, b, c);
  }

  public static <A, B, C, D> Tuple4<A, B, C, D> tuple(A a, B b, C c, D d) {
    return new Tuple4<A, B, C, D>(a, b, c, d);
  }

  public static class Tuple2<A, B> extends Tuple {
    /**
     *
     */
    private static final long serialVersionUID = -6296199669277731380L;
    private A a;
    private B b;

    private Tuple2(A a, B b) {
      this.a = a;
      this.b = b;
    }

    public A _1() {
      return this.a;
    }

    public B _2() {
      return this.b;
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + ((a == null) ? 0 : a.hashCode());
      result = prime * result + ((b == null) ? 0 : b.hashCode());
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj)
        return true;
      if (obj == null)
        return false;
      if (getClass() != obj.getClass())
        return false;
      Tuple2 other = (Tuple2) obj;
      if (a == null) {
        if (other.a != null)
          return false;
      } else if (!a.equals(other.a))
        return false;
      if (b == null) {
        if (other.b != null)
          return false;
      } else if (!b.equals(other.b))
        return false;
      return true;
    }

    @Override
    public String toString() {
      return "Tuple2 [" + a + "," + b + "]";
    }

  }

  public static class Tuple3<A, B, C> extends Tuple {
    /**
     *
     */
    private static final long serialVersionUID = -6296199669277731380L;
    private A a;
    private B b;
    private C c;

    private Tuple3(A a, B b, C c) {
      this.a = a;
      this.b = b;
      this.c = c;
    }

    public A _1() {
      return this.a;
    }

    public B _2() {
      return this.b;
    }

    public C _3() {
      return this.c;
    }

    @Override
    public String toString() {
      return "Tuple3 [a=" + a + ", b=" + b + ", c=" + c + "]";
    }

  }

  public static class Tuple4<A, B, C, D> extends Tuple {
    /**
     *
     */
    private static final long serialVersionUID = -6296199669277731380L;
    private A a;
    private B b;
    private C c;
    private D d;

    private Tuple4(A a, B b, C c, D d) {
      this.a = a;
      this.b = b;
      this.c = c;
      this.d = d;
    }

    public A _1() {
      return this.a;
    }

    public B _2() {
      return this.b;
    }

    public C _3() {
      return this.c;
    }

    public D _4() {
      return this.d;
    }

    @Override
    public String toString() {
      return "Tuple4 [a=" + a + ", b=" + b + ", c=" + c + ", d=" + d + "]";
    }
  }
}
