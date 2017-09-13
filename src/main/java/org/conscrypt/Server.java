package org.conscrypt;

import java.util.concurrent.Future;

public interface Server {
  int port();
  Future<?> start();
  void stop();
}
