/*
 * Copyright (c) 2014 Spotify AB.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.spotify.helios.client.tls;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;

import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;

/**
 * Translates between a {@link RSAPublicKey} and the openssh representation of the key and also
 * it's fingerprint.
 */
// TODO (mbrown): rename
public class Fingerprint {

  private static final BaseEncoding BASE64 = BaseEncoding.base64();
  public static final HashFunction SHA_256 = Hashing.sha256();
  private final RSAPublicKey rsaPublicKey;

  public Fingerprint(final RSAPublicKey rsaPublicKey) {
    this.rsaPublicKey = rsaPublicKey;
  }

  /**
   * Returns the RsaPublicKey in OpenSSH format.
   * <p>The OpenSSH format for a public key is the string 'ssh-rsa ' followed by the base64
   * representation of the encoded key, followed by the comment associated with the key. We can't
   * know the comment so we leave it out.</p>
   * <p>The key is encoded in a byte array in three parts: encoding the type ("ssh-rsa"), the
   * exponent
   * and then the modulus. Each of the three byte arrays is encoded by first encoding the length of
   * the array as 4 bytes (32 bits), followed by the array itself.</p>
   */
  public String toOpenSshFormat() {
    return "ssh-rsa " + BASE64.encode(encodeKey());
  }

  // see above for format of the return byte buffer
  private byte[] encodeKey() {
    final byte[] type = new byte[]{'s', 's', 'h', '-', 'r', 's', 'a'};
    final byte[] exp = rsaPublicKey.getPublicExponent().toByteArray();
    final byte[] mod = rsaPublicKey.getModulus().toByteArray();

    // size needed: the length of each of the three byte arrays, plus the length of each
    // array is encoded as a 4-byte int
    final ByteBuffer bb = ByteBuffer.allocate(3 * 4 + type.length + exp.length + mod.length);
    bb.putInt(type.length);
    bb.put(type);
    bb.putInt(exp.length);
    bb.put(exp);
    bb.putInt(mod.length);
    bb.put(mod);
    return bb.array();
  }

  /**
   * Recent OpenSSH versions report the key fingerprint as base64(sha256(encoded key)). For some
   * reason the base64 padding is omitted.
   */
  public String toFingerprint() {
    return BASE64.omitPadding().encode(SHA_256.hashBytes(encodeKey()).asBytes());
  }
}
