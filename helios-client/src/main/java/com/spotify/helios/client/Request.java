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

import java.net.URI;
import java.util.List;
import java.util.Map;

class Request {

  private final URI uri;
  private final String method;
  private final byte[] entity;
  private final Map<String, List<String>> headers;

  Request(final URI uri, final String method, final byte[] entity,
          final Map<String, List<String>> headers) {

    this.uri = uri;
    this.method = method;
    this.entity = entity;
    this.headers = headers;
  }

  public URI getUri() {
    return uri;
  }

  public String getMethod() {
    return method;
  }

  public byte[] getEntity() {
    return entity;
  }

  public ImmutableMap<String, List<String>> getHeaders() {
    return ImmutableMap.copyOf(headers);
  }

  /** Return a new Request instance with the URI field replaced with the argument. */
  public Request withUri(URI uri) {
    return new Request(uri, this.method, this.entity, this.headers);
  }
}
