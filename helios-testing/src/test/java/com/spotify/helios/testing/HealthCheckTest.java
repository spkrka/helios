/*
 * Copyright (c) 2014 Spotify AB.
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

package com.spotify.helios.testing;

import com.google.common.base.Optional;

import com.spotify.helios.common.descriptors.HealthCheck;
import com.spotify.helios.common.descriptors.HttpHealthCheck;
import com.spotify.helios.common.descriptors.TcpHealthCheck;

import org.junit.Rule;
import org.junit.Test;

import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;

import static java.util.concurrent.TimeUnit.MINUTES;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.experimental.results.PrintableResult.testResult;
import static org.junit.experimental.results.ResultMatchers.isSuccessful;

public class HealthCheckTest extends TemporaryJobsTestBase {

  private static final String HEALTH_CHECK_PORT = "healthCheck";
  private static final String QUERY_PORT = "query";

  @Test
  public void test() throws Exception {
    assertThat(testResult(TestImpl.class), isSuccessful());
  }

  public static class TestImpl {

    @Rule
    public final TemporaryJobs temporaryJobs = temporaryJobsBuilder()
        .client(client)
        .jobPrefix(Optional.of(testTag).get())
        .deployTimeoutMillis(MINUTES.toMillis(3))
        .build();

    @Test
    public void testTcpCheck() throws Exception {
      // running netcat twice on different ports lets us verify the health check actually executed
      // because otherwise we wouldn't be able to connect to the second port.
      final TemporaryJob job = temporaryJobs.job()
          .command("sh", "-c", "nc -l -p 4711 && nc -l -p 4712")
          .port(HEALTH_CHECK_PORT, 4711)
          .port(QUERY_PORT, 4712)
          .tcpHealthCheck(HEALTH_CHECK_PORT)
          .deploy(testHost1);

      // verify health check was set correctly in job
      assertThat(job.job().getHealthCheck(),
                 equalTo((HealthCheck) TcpHealthCheck.of(HEALTH_CHECK_PORT)));

      // verify we can actually connect to the port
      // noinspection EmptyTryBlock
      try (final Socket ignored = new Socket(DOCKER_HOST.address(),
                                             job.address(QUERY_PORT).getPort())) {
      }
    }

    @Test
    public void testHttpCheck() throws Exception {
      // We must include the 'Connection: close' header in the response to prevent the health check
      // http client from making a persistent connection. That would cause netcat to never exit
      // because the connection would remain open.
      final String cmd =
          "(echo -e 'HTTP/1.1 204 No content\\r\\nConnection: close' | nc -l -p 4711)  && " +
          "(echo -e 'HTTP/1.1 204 No content\\r\\nConnection: close' | nc -l -p 4712)";
      final TemporaryJob job = temporaryJobs.job()
          .command("sh", "-c", cmd)
          .port(HEALTH_CHECK_PORT, 4711)
          .port(QUERY_PORT, 4712)
          .httpHealthCheck(HEALTH_CHECK_PORT, "/")
          .deploy(testHost1);

      // verify health check was set correctly in job
      assertThat(job.job().getHealthCheck(),
                 equalTo((HealthCheck) HttpHealthCheck.of(HEALTH_CHECK_PORT, "/")));

      // verify we can actually make http requests
      final URL url = new URL("http", DOCKER_HOST.address(),
                              job.address(QUERY_PORT).getPort(), "/");
      final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      assertThat(connection.getResponseCode(), equalTo(204));
    }

    @Test
    public void testHealthCheck() throws Exception {
      // same as the tcp test above, but uses a HealthCheck
      // object instead of the tcpHealthCheck convenience method
      final HealthCheck healthCheck = TcpHealthCheck.of(HEALTH_CHECK_PORT);
      final TemporaryJob job = temporaryJobs.job()
          .command("sh", "-c", "nc -l -p 4711 && nc -l -p 4712")
          .port(HEALTH_CHECK_PORT, 4711)
          .port(QUERY_PORT, 4712)
          .healthCheck(healthCheck)
          .deploy(testHost1);

      // verify health check was set correctly in job
      assertThat(job.job().getHealthCheck(), equalTo(healthCheck));

      // verify we can actually connect to the port
      // noinspection EmptyTryBlock
      try (final Socket ignored = new Socket(DOCKER_HOST.address(),
                                             job.address(QUERY_PORT).getPort())) {
      }
    }
  }

}