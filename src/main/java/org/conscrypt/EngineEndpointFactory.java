package org.conscrypt;

import java.security.Provider;

final class EngineEndpointFactory implements EndpointFactory {
  private final Provider provider;

  EngineEndpointFactory(Provider provider) {
    this.provider = provider;
  }

  @Override
  public Client newClient(int port, boolean useAlpn) {
    return new EngineClient(TestUtils.newClientContext(provider), port, useAlpn);
  }

  @Override
  public Server newServer(boolean useAlpn) {
    return new EngineServer(TestUtils.newServerContext(provider), useAlpn);
  }
}
