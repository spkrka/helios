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

package com.spotify.helios.agent;

import com.google.common.io.CharStreams;

import com.spotify.docker.client.DockerClient;
import com.spotify.docker.client.DockerException;
import com.spotify.docker.client.DockerHost;
import com.spotify.helios.common.descriptors.DockerVersion;
import com.spotify.helios.common.descriptors.HostInfo;
import com.spotify.helios.servicescommon.coordination.NodeUpdaterFactory;
import com.spotify.helios.servicescommon.coordination.Paths;
import com.spotify.helios.servicescommon.coordination.ZooKeeperNodeUpdater;
import com.sun.management.OperatingSystemMXBean;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Charsets.UTF_8;
import static com.google.common.base.Throwables.propagate;
import static java.util.Objects.requireNonNull;

/**
 * Reports various bits of system information to ZK so it can be viewed via the the API.
 */
public class HostInfoReporter extends SignalAwaitingService {


  private final OperatingSystemMXBean operatingSystemMXBean;
  private final ZooKeeperNodeUpdater nodeUpdater;
  private final int interval;
  private final TimeUnit timeUnit;
  private final DockerClient dockerClient;
  private final DockerHost dockerHost;

  HostInfoReporter(OperatingSystemMXBean operatingSystemMXBean,
                   NodeUpdaterFactory nodeUpdaterFactory, String host, DockerClient dockerClient,
                   DockerHost dockerHost, int interval, TimeUnit timeUnit, CountDownLatch latch) {

    super(latch);
    this.operatingSystemMXBean = requireNonNull(operatingSystemMXBean, "operatingSystemMXBean");
    final String hostInfoPath = Paths.statusHostInfo(requireNonNull(host, "host"));
    this.nodeUpdater = nodeUpdaterFactory.create(hostInfoPath);
    this.dockerClient = requireNonNull(dockerClient, "dockerClient");
    this.dockerHost = requireNonNull(dockerHost, "dockerHost");
    this.interval = interval;
    this.timeUnit = requireNonNull(timeUnit, "timeUnit");
  }

  @Override
  protected void runOneIteration() throws InterruptedException {
    final String hostname = exec("uname -n").trim();
    final String uname = exec("uname -a").trim();

    final HostInfo hostInfo = HostInfo.newBuilder()
        .setArchitecture(operatingSystemMXBean.getArch())
        .setCpus(Runtime.getRuntime().availableProcessors())
        .setHostname(hostname)
        .setLoadAvg(operatingSystemMXBean.getSystemLoadAverage())
        .setOsName(operatingSystemMXBean.getName())
        .setOsVersion(operatingSystemMXBean.getVersion())
        .setMemoryFreeBytes(operatingSystemMXBean.getFreePhysicalMemorySize())
        .setMemoryTotalBytes(operatingSystemMXBean.getTotalPhysicalMemorySize())
        .setSwapFreeBytes(operatingSystemMXBean.getFreeSwapSpaceSize())
        .setSwapTotalBytes(operatingSystemMXBean.getTotalSwapSpaceSize())
        .setUname(uname)
        .setDockerVersion(dockerVersion())
        .setDockerHost(dockerHost())
        .setDockerCertPath(dockerHost.dockerCertPath())
        .build();

    nodeUpdater.update(hostInfo.toJsonBytes());
  }

  private DockerVersion dockerVersion() throws InterruptedException {
    try {
      final com.spotify.docker.client.messages.Version version = dockerClient.version();
      return version == null ? null : dockerVersion(version);
    } catch (DockerException e) {
      return null;
    }
  }

  private DockerVersion dockerVersion(final com.spotify.docker.client.messages.Version version) {
    return DockerVersion.builder()
        .apiVersion(version.apiVersion())
        .arch(version.arch())
        .gitCommit(version.gitCommit())
        .goVersion(version.goVersion())
        .kernelVersion(version.kernelVersion())
        .os(version.os())
        .version(version.version())
        .build();
  }

  private String dockerHost() {
    final String host = dockerHost.host();
    if (host.startsWith("unix://")) {
      return host;
    } else {
      return "tcp://" + host;
    }
  }

  @Override
  protected ScheduledFuture<?> schedule(final Runnable runnable,
                                        final ScheduledExecutorService executorService) {
    return executorService.scheduleWithFixedDelay(runnable, 0, interval, timeUnit);
  }

  private String exec(final String command) {
    try {
      final Process process = Runtime.getRuntime().exec(command);
      return CharStreams.toString(new InputStreamReader(process.getInputStream(), UTF_8));
    } catch (IOException e) {
      throw propagate(e);
    }
  }
}
