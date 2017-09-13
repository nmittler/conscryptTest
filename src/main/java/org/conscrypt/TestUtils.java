package org.conscrypt;

import com.google.common.base.Charsets;
import com.google.common.io.BaseEncoding;
import com.google.common.io.CharStreams;
import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

/**
 * Common utility functions useful for writing tests.
 */
class TestUtils {
  static final String ALPN_PROTOCOL = "testProtocol";
  private static final String MESSAGE = "Hello";
  private static final byte[] MESSAGE_BYTES = MESSAGE.getBytes(StandardCharsets.UTF_8);
  private static final ByteBuffer MESSAGE_BUFFER =
      ByteBuffer.wrap(MESSAGE_BYTES).asReadOnlyBuffer();
  static final int MESSAGE_LENGTH = MESSAGE_BYTES.length;

  private static final Pattern KEY_PATTERN = Pattern.compile(
      "-+BEGIN\\s+.*PRIVATE\\s+KEY[^-]*-+(?:\\s|\\r|\\n)+" + // Header
          "([a-z0-9+/=\\r\\n]+)" +                       // Base64 text
          "-+END\\s+.*PRIVATE\\s+KEY[^-]*-+",            // Footer
      Pattern.CASE_INSENSITIVE);

  static ByteBuffer newMessage() {
    return MESSAGE_BUFFER.duplicate();
  }

  static byte[] messageBytes() {
    return MESSAGE_BYTES;
  }

  /**
   * Saves a file from the classpath resources in src/main/resources/certs as a file on the
   * filesystem.
   *
   * @param name name of a file in src/main/resources/certs.
   */
  static File loadCert(String name) throws IOException {
    InputStream in = TestUtils.class.getResourceAsStream("/certs/" + name);
    File tmpFile = File.createTempFile(name, "");
    tmpFile.deleteOnExit();

    BufferedWriter writer = new BufferedWriter(new FileWriter(tmpFile));
    try {
      int b;
      while ((b = in.read()) != -1) {
        writer.write(b);
      }
    } finally {
      writer.close();
    }

    return tmpFile;
  }

  static void wait(Future<?> future) {
    try {
      future.get(10000, TimeUnit.SECONDS);
    } catch (InterruptedException | TimeoutException | ExecutionException e) {
      throw new RuntimeException(e);
    }
  }

  static SSLContext newClientContext(Provider provider) {
    try {
      File certChainFile = loadCert("ca.pem");
      KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
      ks.load(null, null);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) cf.generateCertificate(
          new BufferedInputStream(new FileInputStream(certChainFile)));
      X500Principal principal = cert.getSubjectX500Principal();
      ks.setCertificateEntry(principal.getName("RFC2253"), cert);

      // Set up trust manager factory to use our key store.
      TrustManagerFactory trustManagerFactory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(ks);
      SSLContext context = SSLContext.getInstance("TLS", provider);
      context.init(null, trustManagerFactory.getTrustManagers(), null);
      return context;
    } catch (IOException | KeyStoreException | NoSuchAlgorithmException | KeyManagementException
        | CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  static SSLContext newServerContext(Provider provider) {
    try {
      File certChainFile = TestUtils.loadCert("server1.pem");
      File keyFile = TestUtils.loadCert("server1.key");

      KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
      ks.load(null, null);

      // Read the cert.
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      X509Certificate cert = (X509Certificate) cf.generateCertificate(
          new BufferedInputStream(new FileInputStream(certChainFile)));

      // Read the private key.
      byte[] keyData = readPrivateKey(keyFile);
      KeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
      PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

      ks.setKeyEntry("key", key, new char[0], new Certificate[] {cert});
      KeyManagerFactory kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(ks, new char[0]);

      // Set up trust manager factory to use our key store.
      TrustManagerFactory trustManagerFactory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(ks);
      SSLContext context = SSLContext.getInstance("TLS", provider);
      context.init(kmf.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
      return context;
    } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException
        | KeyException | InvalidKeySpecException | UnrecoverableKeyException e) {
      throw new RuntimeException(e);
    }
  }

  private static byte[] readPrivateKey(File file) throws KeyException {
    String content = readPemFileContent(file);

    Matcher m = KEY_PATTERN.matcher(content);
    if (!m.find()) {
      throw new KeyException("could not find a PKCS #8 private key in input stream" +
          " (see http://netty.io/wiki/sslcontextbuilder-and-private-key.html for more information)");
    }

    String data = m.group(1).replace("\n", "");
    return BaseEncoding.base64().decode(data);
  }

  private static String readPemFileContent(File file) {
    InputStream in = null;
    Reader reader = null;
    try {
      in = new FileInputStream(file);
      reader = new InputStreamReader(in, Charsets.US_ASCII);
      return CharStreams.toString(reader);
    } catch (IOException e) {
      throw new RuntimeException(e);
    } finally {
      try {
        if (in != null) {
          in.close();
        }
        if (reader != null) {
          reader.close();
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }

  private TestUtils() {
  }
}
