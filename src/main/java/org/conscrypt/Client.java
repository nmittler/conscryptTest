package org.conscrypt;

import java.util.concurrent.Future;

interface Client {
  Future<?> start();
  void sendMessage();
  Future<?> readReply();
  void stop();
}
