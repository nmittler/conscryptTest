package org.conscrypt;

import javax.net.ssl.SSLContext;

public interface EndpointFactory {
  Client newClient(int port, boolean useAlpn);
  Server newServer(boolean useAlpn);
}
