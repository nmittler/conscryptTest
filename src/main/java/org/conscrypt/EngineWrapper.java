package org.conscrypt;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

final class EngineWrapper {
  private static final ByteBuffer EMPTY_BUFFER = ByteBuffer.allocateDirect(0);

  private final SSLEngine engine;
  private final ByteBuffer inboundPacketBuffer;
  private final ByteBuffer inboundAppBuffer;
  private final ByteBuffer outboundPacketBuffer;

  EngineWrapper(SSLEngine engine) {
    this.engine = engine;
    inboundPacketBuffer =
        ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
    inboundAppBuffer =
        ByteBuffer.allocateDirect(engine.getSession().getApplicationBufferSize());
    outboundPacketBuffer =
        ByteBuffer.allocateDirect(engine.getSession().getPacketBufferSize());
  }

  SSLEngine engine() {
    return engine;
  }

  void doHandshake(ByteChannel channel) throws IOException {
    engine.beginHandshake();

    HandshakeStatus status = engine.getHandshakeStatus();
    boolean done = false;
    while (!done) {
      switch (status) {
        case NEED_WRAP: {
          status = wrap(EMPTY_BUFFER, channel).getHandshakeStatus();
          break;
        }
        case NEED_UNWRAP: {
          status = unwrap(channel).getHandshakeStatus();
          break;
        }
        case NEED_TASK: {
          runDelegatedTasks();
          status = engine.getHandshakeStatus();
          break;
        }
        default: {
          done = true;
          break;
        }
      }
    }
  }

  void sendMessage(ByteChannel channel) throws IOException {
    SSLEngineResult result = wrap(TestUtils.newMessage(), channel);
    if (result.getStatus() != Status.OK) {
      throw new RuntimeException("Wrap failed. Status: " + result.getStatus());
    }
  }

  void readMessage(ByteChannel channel) throws IOException {
    int totalProduced = 0;
    while (true) {
      SSLEngineResult result = unwrap(channel);
      switch (result.getStatus()) {
        case OK:
          totalProduced += result.bytesProduced();
          if (totalProduced == TestUtils.MESSAGE_LENGTH) {
            return;
          }
          // Read more data.
          break;
        case BUFFER_UNDERFLOW:
          // Read more data.
          break;
        default:
          throw new RuntimeException("Failed reading message: " + result);
      }
    }
  }

  private SSLEngineResult wrap(ByteBuffer src, ByteChannel channel) throws IOException {
    outboundPacketBuffer.clear();

    // Check if the engine has bytes to wrap.
    SSLEngineResult result = engine.wrap(src, outboundPacketBuffer);

    // Write any wrapped bytes to the socket.
    outboundPacketBuffer.flip();

    do {
      channel.write(outboundPacketBuffer);
    } while (outboundPacketBuffer.hasRemaining());

    return result;
  }

  private SSLEngineResult unwrap(ByteChannel channel) throws IOException {
    // Unwrap any available bytes from the socket.
    int bytesRead = channel.read(inboundPacketBuffer);
    //log("Read bytes: " + bytesRead);
    if (bytesRead == -1) {
      throw new EOFException();
    }

    if (bytesRead == 0) {
      // Sleep for a bit to allow the socket to buffer.
      try {
        Thread.sleep(10);
      } catch (InterruptedException ignore) {
        // Ignored.
      }
    }

    // Just clear the app buffer - we don't really use it.
    inboundAppBuffer.clear();
    inboundPacketBuffer.flip();
    SSLEngineResult result = engine.unwrap(inboundPacketBuffer, inboundAppBuffer);

    // Compact for the next socket read.
    inboundPacketBuffer.compact();
    return result;
  }

  /*private void log(String msg) {
    System.err.println((engine.getUseClientMode() ? "[Client] " : "[Server] ") + msg);
  }*/
  private void runDelegatedTasks() {
    for (;;) {
      Runnable task = engine.getDelegatedTask();
      if (task == null) {
        break;
      }
      task.run();
    }
  }
}
