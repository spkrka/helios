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

package com.spotify.helios.client;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.net.InetAddresses;

import com.spotify.helios.client.HttpsHandlers.CertificateFileHttpsHandler;
import com.spotify.helios.client.HttpsHandlers.SshAgentHttpsHandler;
import com.spotify.sshagentproxy.AgentProxy;
import com.spotify.sshagentproxy.Identity;

import org.hamcrest.CustomTypeSafeMatcher;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HttpsURLConnection;

import static com.google.common.io.Resources.getResource;
import static org.junit.Assert.assertSame;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthenticatingHttpConnectorTest {

  private static final String USER = "user";
  private static final Path CERTIFICATE_PATH = Paths.get(getResource("UIDCACert.pem").getPath());
  private static final Path KEY_PATH = Paths.get(getResource("UIDCACert.key").getPath());

  private static final String DEFAULT_METHOD = "GET";
  private static final byte[] DEFAULT_ENTITY = new byte[0];
  private static final ImmutableMap<String, List<String>> DEFAULT_HEADERS = ImmutableMap.of();

  private final DefaultHttpConnector connector = mock(DefaultHttpConnector.class);
  private List<Endpoint> endpoints;

  @Before
  public void setUp() throws Exception {
    endpoints = ImmutableList.of(
        endpoint(new URI("https://server1.example"), InetAddresses.forString("192.168.0.1")),
        endpoint(new URI("https://server2.example"), InetAddresses.forString("192.168.0.2"))
    );
  }

  private static Endpoint endpoint(final URI uri, final InetAddress ip) {
    return new Endpoint() {
      @Override
      public URI getUri() {
        return uri;
      }

      @Override
      public InetAddress getIp() {
        return ip;
      }
    };
  }

  private AuthenticatingHttpConnector createAuthenticatingConnector(
      final Optional<AgentProxy> proxy, final List<Identity> identities) {

    final EndpointIterator endpointIterator = EndpointIterator.of(endpoints);
    return new AuthenticatingHttpConnector(USER, proxy, Optional.<Path>absent(),
                                           Optional.<Path>absent(), endpointIterator, connector,
                                           identities);
  }

  private AuthenticatingHttpConnector createAuthenticatingConnectorWithCertFile() {

    final EndpointIterator endpointIterator = EndpointIterator.of(endpoints);

    return new AuthenticatingHttpConnector(USER, Optional.<AgentProxy>absent(),
                                           Optional.of(CERTIFICATE_PATH), Optional.of(KEY_PATH),
                                           endpointIterator, connector);
  }

  /**
   * A Matcher for Requests that asserts that the Request matches the given headers, method,
   * entity, and that the Request matches the {@link #matchesEndpoint(Endpoint, Request)} test for
   * any of the preconfigured Endpoints.
   */
  private CustomTypeSafeMatcher<Request> matchesAnyEndpoint(final Map<String, List<String>> headers,
                                                            final String method,
                                                            final byte[] entity,
                                                            final String path) {
    return new CustomTypeSafeMatcher<Request>(
        "A request matching one of the endpoints in " + endpoints) {
      @Override
      protected boolean matchesSafely(final Request actual) {

        return headers.equals(actual.getHeaders()) &&
               method.equals(actual.getMethod()) &&
               Arrays.equals(entity, actual.getEntity()) &&
               matchesAnyEndpointPath(actual);
      }

      private boolean matchesAnyEndpointPath(final Request actual) {
        for (Endpoint endpoint : endpoints) {
          if (matchesEndpoint(endpoint, actual) && actual.getUri().getPath().equals(path)) {
            return true;
          }
        }
        return false;
      }
    };
  }

  /**
   * Tests that the Request instance has a URI which "matches" the scheme of the Endpoint's URI and
   * that the URI's host matches the Endpoint's ip.hostaddress
   */
  private static boolean matchesEndpoint(Endpoint endpoint, Request request) {
    final URI requestUri = request.getUri();
    return requestUri.getScheme().equals(endpoint.getUri().getScheme()) &&
           requestUri.getHost().equals(endpoint.getIp().getHostAddress());
  }

  /** Sets up a Matcher for Requests that uses the default headers, method and entity. */
  private CustomTypeSafeMatcher<Request> matchesAnyEndpoint(String path) {
    return matchesAnyEndpoint(DEFAULT_HEADERS, DEFAULT_METHOD, DEFAULT_ENTITY, path);
  }

  /** Sets up a Request using all of the default values */
  private Request newRequest(URI uri) {
    return new Request(uri, DEFAULT_METHOD, DEFAULT_ENTITY, DEFAULT_HEADERS);
  }

  private Identity mockIdentity() {
    final Identity identity = mock(Identity.class);
    when(identity.getComment()).thenReturn("a comment");
    return identity;
  }

  @Test
  public void testNoIdentities_ResponseIsOK() throws Exception {
    final AuthenticatingHttpConnector authConnector = createAuthenticatingConnector(
        Optional.<AgentProxy>absent(),
        ImmutableList.<Identity>of());

    final String path = "/foo/bar";

    final HttpsURLConnection connection = mock(HttpsURLConnection.class);
    when(connector.connect(argThat(matchesAnyEndpoint(path)))).thenReturn(connection);
    when(connection.getResponseCode()).thenReturn(200);

    authConnector.connect(newRequest(new URI("https://helios" + path)));

    verify(connector, never()).setExtraHttpsHandler(any(HttpsHandler.class));
  }

  @Test
  public void testCertFile_ResponseIsOK() throws Exception {
    final AuthenticatingHttpConnector authConnector = createAuthenticatingConnectorWithCertFile();

    final String path = "/foo/bar";

    final HttpsURLConnection connection = mock(HttpsURLConnection.class);
    when(connector.connect(argThat(matchesAnyEndpoint(path)))).thenReturn(connection);
    when(connection.getResponseCode()).thenReturn(200);

    authConnector.connect(newRequest(new URI("https://helios" + path)));

    verify(connector).setExtraHttpsHandler(certFileHttpsHandlerWithArgs(
        USER, CERTIFICATE_PATH, KEY_PATH));
  }

  @Test
  public void testOneIdentity_ResponseIsOK() throws Exception {

    final AgentProxy proxy = mock(AgentProxy.class);
    final Identity identity = mockIdentity();

    final AuthenticatingHttpConnector authConnector =
        createAuthenticatingConnector(Optional.of(proxy), ImmutableList.of(identity));

    final String path = "/another/one";

    final HttpsURLConnection connection = mock(HttpsURLConnection.class);
    when(connector.connect(argThat(matchesAnyEndpoint(path)))).thenReturn(connection);
    when(connection.getResponseCode()).thenReturn(200);

    authConnector.connect(newRequest(new URI("https://helios" + path)));

    verify(connector).setExtraHttpsHandler(sshAgentHttpsHandlerWithArgs(USER, proxy, identity));
  }

  @Test
  public void testOneIdentity_ResponseIsUnauthorized() throws Exception {

    final AgentProxy proxy = mock(AgentProxy.class);
    final Identity identity = mockIdentity();

    final AuthenticatingHttpConnector authConnector =
        createAuthenticatingConnector(Optional.of(proxy), ImmutableList.of(identity));

    final String path = "/another/one";

    final HttpsURLConnection connection = mock(HttpsURLConnection.class);
    when(connector.connect(argThat(matchesAnyEndpoint(path)))).thenReturn(connection);
    when(connection.getResponseCode()).thenReturn(401);

    final URI uri = new URI("https://helios" + path);
    final HttpURLConnection returnedConnection = authConnector.connect(newRequest(uri));

    verify(connector).setExtraHttpsHandler(sshAgentHttpsHandlerWithArgs(USER, proxy, identity));

    assertSame("If there is only one identity do not expect any additional endpoints to "
               + "be called after the first returns Unauthorized",
        returnedConnection, connection);
  }

  private static HttpsHandler sshAgentHttpsHandlerWithArgs(
      final String user, final AgentProxy agentProxy, final Identity identity) {
    return argThat(new ArgumentMatcher<HttpsHandler>() {
      @Override
      public boolean matches(final Object handler) {
        if (!(handler instanceof SshAgentHttpsHandler)) {
          return false;
        }

        final SshAgentHttpsHandler authHandler = (SshAgentHttpsHandler) handler;
        return authHandler.getUser().equals(user) &&
               authHandler.getAgentProxy().equals(agentProxy) &&
               authHandler.getIdentity().equals(identity);
      }
    });
  }

  private static HttpsHandler certFileHttpsHandlerWithArgs(
      final String user, final Path certificatePath, final Path keyPath) {
    return argThat(new ArgumentMatcher<HttpsHandler>() {
      @Override
      public boolean matches(final Object handler) {
        if (!(handler instanceof HttpsHandlers.CertificateFileHttpsHandler)) {
          return false;
        }

        final CertificateFileHttpsHandler authHandler = (CertificateFileHttpsHandler) handler;
        return authHandler.getUser().equals(user) &&
               authHandler.getClientCertificatePath().equals(certificatePath) &&
               authHandler.getClientKeyPath().equals(keyPath);
      }
    });
  }
}
