package org.conscrypt;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.Provider;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Test app for the conscrypt security provider.
 */
public class Test {

  public static void main(String[] args) {
    try {
      // Add conscrypt as the preferred provider.
      Provider provider = new OpenSSLProvider();
      //Provider provider = Security.getProvider("SunJSSE");

      // Start the server.
      Server server = new Server();
      int port = server.start(provider);

      Client client = new Client(provider, port);
      client.sendMessage();
      client.awaitResponse();

      server.shutdown();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }

  private static final class Client {

    private final SSLSocket sslSocket;

    Client(Provider provider, int port) {
      try {
        // Create the client and send a message.
        SSLSocketFactory factory = TestUtils
            .newSslSocketFactory(provider, TestUtils.loadCert("ca.pem"));
        System.err.println("Client socket factory: " + factory.getClass().getName());
        sslSocket = (SSLSocket) factory.createSocket("localhost", port);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    void sendMessage() {
      try {
        OutputStreamWriter writer = new OutputStreamWriter(sslSocket.getOutputStream());
        writer.write("hello!\n");
        writer.flush();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    void awaitResponse() {
      try {
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(sslSocket.getInputStream()));

        String message;
        while ((message = reader.readLine()) != null) {
          message("Client received message back from Server: " + message);
          break;
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }
  }

  private static final class Server {

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private SSLServerSocket serverSocket;

    int start(Provider provider) {
      try {
        File cert = TestUtils.loadCert("server1.pem");
        File key = TestUtils.loadCert("server1.key");
        SSLServerSocketFactory sslserversocketfactory = TestUtils
            .newSslServerSocketFactory(provider, cert, key);
        serverSocket =
            (SSLServerSocket) sslserversocketfactory.createServerSocket(0);
        System.err.println("Server socket: " + serverSocket.getClass().getName());

        // Start the message handler.
        executor.submit(new Handler());

        // Return the port that the server is running on.
        SocketAddress localAddr = serverSocket.getLocalSocketAddress();
        return ((InetSocketAddress) localAddr).getPort();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    void shutdown() {
      try {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    private final class Handler implements Runnable {

      public void run() {
        try {
          SSLSocket sslsocket = (SSLSocket) serverSocket.accept();

          BufferedReader reader = new BufferedReader(
              new InputStreamReader(sslsocket.getInputStream()));

          String string;
          while ((string = reader.readLine()) != null) {
            message("Server received message from Client: " + string);
            break;
          }

          BufferedWriter writer = new BufferedWriter(
              new OutputStreamWriter(sslsocket.getOutputStream()));
          writer.write("*sigh* ... what???\n");
          writer.flush();
        } catch (Exception e) {
          e.printStackTrace();
          throw new RuntimeException(e);
        }
      }
    }
  }

  private static void message(String msg) {
    System.out.println(msg);
    System.out.flush();
  }
}
