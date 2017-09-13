package org.conscrypt;

import static org.conscrypt.TestUtils.ALPN_PROTOCOL;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SocketChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

public class EngineClient implements Client {
  private final EngineWrapper engineWrapper;
  private final int port;
  private final boolean useAlpn;
  private SocketChannel channel;
  private ExecutorService executor;

  EngineClient(SSLContext context, int port, boolean useAlpn) {
    this.port = port;
    this.useAlpn = useAlpn;

    // Create and configure the engine.
    SSLEngine engine = context.createSSLEngine();
    engine.setUseClientMode(true);
    if (useAlpn) {
      if (!Conscrypt.isConscrypt(engine)) {
        throw new IllegalArgumentException("ALPN is only supported for Conscrypt sockets");
      }
      Conscrypt.setAlpnProtocols(engine, new String[] {"foo", "bar", ALPN_PROTOCOL});
    }

    engineWrapper = new EngineWrapper(engine);
  }

  @Override
  public Future<?> start() {
    try {
      executor = Executors.newSingleThreadExecutor();
      channel = SocketChannel.open(new InetSocketAddress("localhost", port));
      channel.configureBlocking(false);

      return executor.submit(() -> {
        try {
          engineWrapper.doHandshake(channel);

          if (useAlpn) {
            assertEquals(ALPN_PROTOCOL, Conscrypt.getAlpnSelectedProtocol(engineWrapper.engine()));
          }
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      });
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void sendMessage() {
    try {
      engineWrapper.sendMessage(channel);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Future<?> readReply() {
    return executor.submit(() -> {
      try {
        engineWrapper.readMessage(channel);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
  }

  @Override
  public void stop() {
    try {
      if (channel != null) {
        channel.close();
      }
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
  public String toString() {
    return String.format("Client(type=%s, provider=%s, useAlpn=%b)", "Engine",
        Conscrypt.isConscrypt(engineWrapper.engine()) ? "Conscrypt" : "JDK", useAlpn);
  }
}
