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

import com.google.common.collect.ImmutableMap;
import com.google.common.util.concurrent.ListenableFuture;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.spotify.helios.common.HeliosException;
import com.spotify.helios.common.Json;
import com.spotify.helios.common.descriptors.HostStatus;

import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import static com.google.common.util.concurrent.Futures.immediateFuture;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class HeliosClientTest {

  @Rule
  public ExpectedException exception = ExpectedException.none();

  private final RequestDispatcher dispatcher = mock(RequestDispatcher.class);
  private final HeliosClient client = new HeliosClient("homer", dispatcher);

  private final ObjectMapper objectMapper = new ObjectMapper();

  private final byte[] emptyByteArray = new byte[0];
  private Map<String, List<String>> emptyHeaders = ImmutableMap.of();

  private final URI baseURI = URI.create("http://helios/");

  private void expectRequest(final String method, final String relativePath,
                             final int responseCode, final ObjectNode responseBody) {

    expectRequest(method, relativePath, responseCode, Json.asBytesUnchecked(responseBody));
  }

  private void expectRequest(final String method, final String relativePath,
                             final int responseCode, final String responseBody) {

    expectRequest(method, relativePath, responseCode, responseBody.getBytes());
  }

  /** Set up a stub on the requestDispatcher mock */
  @SuppressWarnings("unchecked")
  private void expectRequest(final String method, final String relativePath,
                             final int responseCode, final byte[] responseBody) {

    final URI uri = baseURI.resolve(relativePath);
    final Response response = new Response(responseCode, responseBody, emptyHeaders);

    when(dispatcher.request(eq(uri), anyString(), eq(emptyByteArray), anyMap()))
        .thenReturn(immediateFuture(response));
  }

  /**
   * Set up expectations on the ExpectedException of an ExecutionException being thrown with a
   * HeliosException whose message contains the given string.
   */
  private void expectHeliosExceptionWithMessage(final String message) {
    exception.expect(ExecutionException.class);
    exception.expectCause(Matchers.<HeliosException>instanceOf(HeliosException.class));
    exception.expectMessage(message);
  }

  @Test
  public void testHostStatus() throws Exception {

    final ObjectNode json = objectMapper.createObjectNode()
        .put("status", "UP");
    json.putObject("jobs");
    json.putObject("statuses");

    expectRequest("GET", "/hosts/hal9000/status?user=homer", 200, json);

    final ListenableFuture<HostStatus> future = client.hostStatus("hal9000");

    assertNotNull(future);
    assertTrue(future.isDone());
    assertNotNull(future.get());
  }

  @Test
  public void testHostStatus_ResponseIsNotJson() throws Exception {
    expectRequest("GET", "/hosts/hal9000/status?user=homer", 200, "This is not JSON");

    expectHeliosExceptionWithMessage("bad reply");

    final ListenableFuture<HostStatus> future = client.hostStatus("hal9000");
    future.get();
  }
}
