package org.oidc.testutil;

import com.auth0.jwt.exceptions.oicmsg_exceptions.ImportException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.JWKException;
import com.auth0.jwt.exceptions.oicmsg_exceptions.UnknownKeyType;
import com.auth0.jwt.exceptions.oicmsg_exceptions.ValueError;
import com.auth0.msg.KeyBundle;
import com.auth0.msg.KeyJar;
import com.auth0.msg.KeyUtils;
import com.auth0.msg.RSAKey;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

/** Utility class for tests. */
public class KeyUtil {

  private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa-public.pem";
  private static final String PRIVATE_KEY_FILE = "src/test/resources/rsa-private.pem";

  /**
   * Get a RSA prv key.
   * 
   * @return RSA key
   * @throws IOException
   *           if something unexpected occurs
   * @throws JWKException
   *           if something unexpected occurs
   * @throws CertificateException
   *           if something unexpected occurs
   */
  public static RSAKey getRSAPrvKey() throws IOException, JWKException, CertificateException {
    return RSAKey.loadKey(KeyUtils.getRSAPrivateKeyFromFile(PRIVATE_KEY_FILE));
  }

  /**
   * Get a RSA pub key.
   * 
   * @return RSA key
   * @throws IOException
   *           if something unexpected occurs
   * @throws JWKException
   *           if something unexpected occurs
   * @throws CertificateException
   *           if something unexpected occurs
   */
  public static RSAKey getRSAPubKey() throws IOException, JWKException, CertificateException {
    return RSAKey.loadKey(KeyUtils.getRSAPrivateKeyFromFile(PUBLIC_KEY_FILE));
  }

  /**
   * Creates keyjar with one private rsa key.
   * 
   * @return keyjar
   * @throws JWKException
   *           if something unexpected occurs
   * @throws IOException
   *           if something unexpected occurs
   * 
   */
  public static KeyJar getKeyJarPrv(String owner) throws ImportException, UnknownKeyType,
      IllegalArgumentException, ValueError, IOException, JWKException {
    KeyJar keyJarOfPrivateKeys = new KeyJar();
    ArrayList<String> usesPrv = new ArrayList<String>();
    usesPrv.add("sig");
    usesPrv.add("dec");
    KeyBundle keyBundlePrv = KeyBundle.keyBundleFromLocalFile(PRIVATE_KEY_FILE, "der", usesPrv);
    keyJarOfPrivateKeys.addKeyBundle(owner, keyBundlePrv);
    return keyJarOfPrivateKeys;
  }

  /**
   * Creates keyjar with one public rsa key.
   * 
   * @return keyjar
   * @throws JWKException
   *           if something unexpected occurs
   * @throws IOException
   *           if something unexpected occurs
   * 
   */
  public static KeyJar getKeyJarPub(String owner) throws ImportException, UnknownKeyType,
      IllegalArgumentException, ValueError, IOException, JWKException {
    KeyJar keyJarOfPublicKeys = new KeyJar();
    ArrayList<String> usesPub = new ArrayList<String>();
    usesPub.add("ver");
    usesPub.add("enc");
    KeyBundle keyBundlePub = KeyBundle.keyBundleFromLocalFile(PUBLIC_KEY_FILE, "der", usesPub);
    keyJarOfPublicKeys.addKeyBundle(owner, keyBundlePub);
    return keyJarOfPublicKeys;
  }

}
