package org.conscrypt;

import static org.conscrypt.TestUtils.ALPN_PROTOCOL;
import static org.conscrypt.TestUtils.MESSAGE_LENGTH;
import static org.conscrypt.TestUtils.messageBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.EOFException;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

final class SocketServer implements Server {
  private final SSLServerSocketFactory factory;
  private final boolean useAlpn;
  private SSLServerSocket serverSocket;
  private SSLSocket sslSocket;
  private ExecutorService executor;

  SocketServer(SSLContext context, boolean useAlpn) {
    this.useAlpn = useAlpn;
    factory = context.getServerSocketFactory();
    if (useAlpn && !Conscrypt.isConscrypt(factory)) {
      throw new IllegalArgumentException("ALPN is only supported for Conscrypt sockets");
    }
  }

  @Override
  public int port() {
    return serverSocket.getLocalPort();
  }

  @Override
  public Future<?> start() {
    try {
      executor = Executors.newSingleThreadExecutor();
      serverSocket = (SSLServerSocket) factory.createServerSocket(0);

      // Start the message handler.
      return executor.submit(new AcceptTask());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void stop() {
    try {
      if (sslSocket != null) {
        sslSocket.close();
      }

      serverSocket.close();

      if (executor != null) {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
        executor = null;
      }
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException(e);
    }
  }

  private final class AcceptTask implements Runnable {
    @Override
    public void run() {
      try {
        sslSocket = (SSLSocket) serverSocket.accept();
        if (useAlpn) {
          BiFunction<SSLSocket, List<String>, String> selector =
              (sslSocket, strings) -> TestUtils.ALPN_PROTOCOL;
          Method method = sslSocket.getClass().getMethod(
              "setHandshakeApplicationProtocolSelector", BiFunction.class);
          method.invoke(sslSocket, selector);
        }

        sslSocket.startHandshake();

        if (useAlpn) {
          assertEquals(ALPN_PROTOCOL, Conscrypt.getAlpnSelectedProtocol(sslSocket));
        }

        executor.submit(new EchoTask());
      } catch (Throwable e) {
        e.printStackTrace();
        throw new RuntimeException(e);
      }
    }
  }

  private final class EchoTask implements Runnable {
    @Override
    public void run() {
      try {
        readMessage();
        reply();
      } catch (Throwable e) {
        throw new RuntimeException(e);
      }
    }

    private void readMessage() {
      try {
        byte[] buffer = new byte[MESSAGE_LENGTH];
        int totalRead = 0;
        while (totalRead < MESSAGE_LENGTH) {
          int bytesRead =
              sslSocket.getInputStream().read(buffer, totalRead, MESSAGE_LENGTH - totalRead);
          if (bytesRead == -1) {
            throw new EOFException();
          }
          totalRead += bytesRead;
        }
        assertArrayEquals(messageBytes(), buffer);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }

    private void reply() {
      try {
        sslSocket.getOutputStream().write(messageBytes());
        sslSocket.getOutputStream().flush();
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }

  @Override
  public String toString() {
    return String.format("Server(type=%s, provider=%s, useAlpn=%b)", "Socket",
        Conscrypt.isConscrypt(factory) ? "Conscrypt" : "JDK", useAlpn);
  }
}
