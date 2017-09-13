package org.conscrypt;

import java.security.Provider;
import java.security.Security;
import java.util.concurrent.Future;

/**
 * Main app for testing TLS provider client/server.
 */
public class TestMain {

  public static void main(String[] args) {
    try {
      // Choose the TLS provider
      Provider provider = new OpenSSLProvider();
      //Provider provider = Security.getProvider("SunJSSE");

      // Choose to use socket or engine-based endpoints.
      EndpointFactory endpointFactory = new EngineEndpointFactory(provider);
      //EndpointFactory endpointFactory = new SocketEndpointFactory(provider);

      Server server = endpointFactory.newServer(true);
      Future<?> serverStartFuture = server.start();

      Client client = endpointFactory.newClient(server.port(), true);
      Future<?> clientStartFuture = client.start();

      System.err.println(client);
      System.err.println(server);

      TestUtils.wait(serverStartFuture);
      TestUtils.wait(clientStartFuture);

      client.sendMessage();
      TestUtils.wait(client.readReply());

      server.stop();
      client.stop();

      System.err.println("Done!");
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(1);
    }
  }
}
