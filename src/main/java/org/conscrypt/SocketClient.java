package org.conscrypt;

import static org.conscrypt.TestUtils.ALPN_PROTOCOL;
import static org.conscrypt.TestUtils.MESSAGE_LENGTH;
import static org.conscrypt.TestUtils.messageBytes;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

final class SocketClient implements Client {
  private final SSLSocket sslSocket;
  private final int port;
  private final boolean useAlpn;
  private ExecutorService executor;

  SocketClient(SSLContext context, int port, boolean useAlpn) {
    try {
      this.port = port;
      this.useAlpn = useAlpn;

      // Create and configure the socket.
      SSLSocketFactory factory = context.getSocketFactory();
      sslSocket = (SSLSocket) factory.createSocket();
      if (useAlpn) {
        if (!Conscrypt.isConscrypt(sslSocket)) {
          throw new IllegalArgumentException("ALPN is only supported for Conscrypt sockets");
        }
        Conscrypt.setAlpnProtocols(sslSocket, new String[] {"foo", "bar", TestUtils.ALPN_PROTOCOL});
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Future<?> start() {
    try {
      executor = Executors.newSingleThreadExecutor();
      sslSocket.connect(new InetSocketAddress("localhost", port));

      return executor.submit(() -> {
        try {
          sslSocket.startHandshake();
          if (useAlpn) {
            assertEquals(ALPN_PROTOCOL, Conscrypt.getAlpnSelectedProtocol(sslSocket));
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
      sslSocket.getOutputStream().write(messageBytes());
      sslSocket.getOutputStream().flush();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Future<?> readReply() {
    return executor.submit(() -> {
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
    });
  }

  @Override
  public void stop() {
    try {
      if (sslSocket != null) {
        sslSocket.close();
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
    return String.format("Client(type=%s, provider=%s, useAlpn=%b)", "Socket",
        Conscrypt.isConscrypt(sslSocket) ? "Conscrypt" : "JDK", useAlpn);
  }
}
