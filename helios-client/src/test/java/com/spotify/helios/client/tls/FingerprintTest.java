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

import com.google.common.io.BaseEncoding;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class FingerprintTest {

  // to generate a key:
  // $ ssh-keygen -b 2096 -t rsa -f dummy_rsa
  //
  // leave out the comment as java.security.interfaces.RSAPublicKey and the class being
  // tested ignore it anyway.
  private static final String KEY_IN_OPENSSH_FORMAT =
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCql+i3P8dHKNMsbC4LKnXEureh5tBCao"
      + "Exbw2YbN9HUR6l0sg1PoJfmZBc07J1jG+4UTLXGxHrGQINZM4X2U43/Q2BwbAGDzuKMN"
      + "AQlUn3vqMrBiSt75bw2Yx0ce4KykERf2+NfDIj5mLOH7h2EdmvhIkceilPKiTbFsxsrw"
      + "uZAadDL6LC/90bk19Smfvc3h7j/TvtzBxIK/ciHmTtxSpRtmcCMNWenrDJHgURSNhBXw"
      + "iPb2lhKzeLz167iFAfcUXrEBTxviQWyycBBAhpbH+5zfd3uKqJc1I3TR8CycIpM7ngJa"
      + "5LMWFQuevRz2vmXMNnTxfVavJequmQ+2Umq3Wr";

  // need the above key in PKCS8 format to turn into a RsaPublicKey instance
  // $ ssh-keygen -e -m PKCS8 -f dummy_rsa.pub
  private static final String KEY_IN_PKCS_PEM_FORMAT =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqpfotz/HRyjTLGwuCyp1"
      + "xLq3oebQQmqBMW8NmGzfR1EepdLINT6CX5mQXNOydYxvuFEy1xsR6xkCDWTOF9lO"
      + "N/0NgcGwBg87ijDQEJVJ976jKwYkre+W8NmMdHHuCspBEX9vjXwyI+Zizh+4dhHZ"
      + "r4SJHHopTyok2xbMbK8LmQGnQy+iwv/dG5NfUpn73N4e4/077cwcSCv3Ih5k7cUq"
      + "UbZnAjDVnp6wyR4FEUjYQV8Ij29pYSs3i89eu4hQH3FF6xAU8b4kFssnAQQIaWx/"
      + "uc33d7iqiXNSN00fAsnCKTO54CWuSzFhULnr0c9r5lzDZ08X1WryXqrpkPtlJqt1"
      + "qwIDAQAB";

  private Fingerprint fingerprint;

  @Before
  public void setUp() throws Exception {
    final byte[] decodedKey = BaseEncoding.base64().decode(KEY_IN_PKCS_PEM_FORMAT);
    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    final PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));

    // sanity check
    assertThat(publicKey, instanceOf(RSAPublicKey.class));
    fingerprint = new Fingerprint((RSAPublicKey) publicKey);
  }

  @Test
  public void testOpenSshFormat() throws IOException {
    // remove the comment from the test key
    assertThat(fingerprint.toOpenSshFormat(), is(KEY_IN_OPENSSH_FORMAT));
  }

  @Test
  public void testFingerprint() throws IOException {
    assertThat(fingerprint.toFingerprint(), is("j3kp8QNUACyvUzzr8XiVRjd7JWeuXdtw0VIZubgbRH4"));
  }
}
