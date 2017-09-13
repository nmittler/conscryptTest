package org.conscrypt;

import static org.conscrypt.TestUtils.ALPN_PROTOCOL;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

final class EngineServer implements Server {
  private final ServerSocketChannel serverChannel;
  private final EngineWrapper engineWrapper;
  private final boolean useAlpn;
  private SocketChannel channel;
  private ExecutorService executor;

  EngineServer(SSLContext context, boolean useAlpn) {
    try {
      this.useAlpn = useAlpn;
      serverChannel = ServerSocketChannel.open();

      SSLEngine engine = context.createSSLEngine();
      engine.setUseClientMode(false);
      if (useAlpn) {
        if (!Conscrypt.isConscrypt(engine)) {
          throw new IllegalArgumentException("ALPN is only supported for Conscrypt sockets");
        }
        BiFunction<SSLEngine, List<String>, String> selector =
            (SSLEngine sslEngine, List<String> strings) -> {
              // Just prove that we can get the current cipher without issue.
              String cipherSuite = sslEngine.getSession().getCipherSuite();
              System.err.println("Cipher suite=" + cipherSuite);
              return TestUtils.ALPN_PROTOCOL;
            };
        Method method = engine.getClass().getMethod(
            "setHandshakeApplicationProtocolSelector", BiFunction.class);
        method.invoke(engine, selector);
      }

      engineWrapper = new EngineWrapper(engine);
    } catch (IOException | InvocationTargetException | IllegalAccessException
        | NoSuchMethodException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Future<?> start() {
    try {
      executor = Executors.newSingleThreadExecutor();
      serverChannel.socket().bind(new InetSocketAddress("localhost", 0));
      return executor.submit(new AcceptTask());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void stop() {
    try {
      if (channel != null) {
        channel.close();
        channel = null;
      }

      serverChannel.close();

      if (executor != null) {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
        executor = null;
      }
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public int port() {
    return serverChannel.socket().getLocalPort();
  }

  private final class AcceptTask implements Runnable {
    @Override
    public void run() {
      try {
        channel = serverChannel.accept();
        channel.configureBlocking(false);

        engineWrapper.doHandshake(channel);
        if (useAlpn) {
          assertEquals(ALPN_PROTOCOL, Conscrypt.getAlpnSelectedProtocol(engineWrapper.engine()));
        }

        executor.submit(new EchoTask());
      } catch (Throwable e) {
        throw new RuntimeException(e);
      }
    }
  }

  private final class EchoTask implements Runnable {
    @Override
    public void run() {
      try {
        engineWrapper.readMessage(channel);
        engineWrapper.sendMessage(channel);
      } catch (Throwable e) {
        e.printStackTrace();
        throw new RuntimeException(e);
      }
    }
  }

  @Override
  public String toString() {
    return String.format("Server(type=%s, provider=%s, useAlpn=%b)", "Engine",
        Conscrypt.isConscrypt(engineWrapper.engine()) ? "Conscrypt" : "JDK", useAlpn);
  }
}
