package org.conscrypt;

import java.security.Provider;

final class SocketEndpointFactory implements EndpointFactory {
  private final Provider provider;

  SocketEndpointFactory(Provider provider) {
    this.provider = provider;
  }

  @Override
  public Client newClient(int port, boolean useAlpn) {
    return new SocketClient(TestUtils.newClientContext(provider), port, useAlpn);
  }

  @Override
  public Server newServer(boolean useAlpn) {
    return new SocketServer(TestUtils.newServerContext(provider), useAlpn);
  }
}
