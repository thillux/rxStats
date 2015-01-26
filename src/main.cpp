#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/socket.h>
#include <signal.h>
#include <stdexcept>
#include <string>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

std::atomic_bool g_shallStop;

struct packet_info {
  struct timeval time;
  uint64_t num_packets_rx;
  uint64_t num_packets_tx;
};

std::string getTimeStringUTC(struct timeval tv) {
  struct tm tmBuffer;
  struct tm* timeinfo = gmtime_r(&tv.tv_sec, &tmBuffer);
  if (timeinfo == NULL)
    throw std::runtime_error("gmtime_r() system call failed!");

  char buf[strlen("2014-08-19 07:07:07.007") + 1];
  size_t offset = strlen("2014-08-19 07:07:07");
  strftime(buf, sizeof(buf), "%F %H:%M:%S", timeinfo);
  snprintf(buf + offset,
           sizeof(buf) - offset,
           ".%03d",
           static_cast<int>(tv.tv_usec / 1000));

  return std::string(buf);
}

struct packet_info getPacketStats(nl_sock* sock,
                                  nl_cache* cache,
                                  const std::string& interface) {
  struct packet_info pInfo;
  if (gettimeofday(&pInfo.time, NULL) < 0)
    throw std::runtime_error("gettimeofday() system call failed!");

  struct rtnl_link* link = rtnl_link_get_by_name(cache, interface.c_str());
  assert(link != nullptr);
  int ret_refill = nl_cache_refill(sock, cache);
  assert(ret_refill == 0);
  pInfo.num_packets_rx = rtnl_link_get_stat(link, RTNL_LINK_RX_PACKETS);
  pInfo.num_packets_tx = rtnl_link_get_stat(link, RTNL_LINK_TX_PACKETS);
  rtnl_link_put(link);

  return pInfo;
}

void handleSignal(int s) {
  if (s == SIGINT) {
    std::cerr << "SIGINT catched" << std::endl;
    g_shallStop = true;
  }
}

int main(int argc, char** argv) {
  struct sigaction sigIntHandler;

  sigIntHandler.sa_handler = handleSignal;
  sigemptyset(&sigIntHandler.sa_mask);
  sigIntHandler.sa_flags = 0;

  sigaction(SIGINT, &sigIntHandler, NULL);

  std::cout << "rxStats" << std::endl;

  assert(argc == 2);
  std::string interface(argv[1]);

  std::cout << "Interface: " << interface << std::endl;
  unsigned long updateIntervalMilliseconds = 1000;

  struct nl_sock* sock;
  // Allocate a new netlink socket
  sock = nl_socket_alloc();
  // Connect to link netlink socket on kernel side
  nl_connect(sock, NETLINK_ROUTE);

  struct nl_cache* cache = nullptr;
  int ret_alloc_cache = rtnl_link_alloc_cache(sock, AF_UNSPEC, &cache);
  assert(ret_alloc_cache == 0);
  assert(cache != nullptr);

  while (!g_shallStop) {
    struct packet_info pInfo = getPacketStats(sock, cache, interface);

    std::cout << getTimeStringUTC(pInfo.time) << ": " << pInfo.num_packets_rx
              << " " << pInfo.num_packets_tx << std::endl;

    std::this_thread::sleep_for(
        std::chrono::milliseconds(updateIntervalMilliseconds));
  }

  nl_cache_free(cache);
  cache = nullptr;

  nl_close(sock);
  nl_socket_free(sock);
  sock = nullptr;

  return EXIT_SUCCESS;
}