#include "network.h"
#include "socket-shim.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

#ifdef __EMSCRIPTEN__
/* WASM has no network interfaces — fill with zeros */
int _librist_network_get_macaddr(uint8_t mac[]) {
  memset(mac, 0, 6);
  return 0;
}
#else /* !__EMSCRIPTEN__ */

#ifndef _WIN32
#include <ifaddrs.h>
#ifdef __linux__
#include <netpacket/packet.h>
#elif defined(__GNU__)
#include <sys/ioctl.h>
#include <net/if.h>
#else
#include <net/if_dl.h>
#endif
#else
#include <winsock2.h>
#include <iphlpapi.h>
#endif

int _librist_network_get_macaddr(uint8_t mac[]) {
  char mac_null[6] = {0};
#ifndef _WIN32
#if defined(__GNU__)
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return -1;
#endif
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;
  if (getifaddrs(&ifaddr) == -1) {
#if defined(__GNU__)
    close(sock);
#endif
    return -1;
  } else {
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
#ifdef __linux__

      if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)) {
        struct sockaddr_ll *s = (struct sockaddr_ll *)ifa->ifa_addr;
        if (memcmp(mac_null, s->sll_addr, 6)) {
          memcpy(mac, s->sll_addr, 6);
          break;
        }
      }
#elif defined(__GNU__)
      struct ifreq ifr;
      strcpy(ifr.ifr_name, ifa->ifa_name);
      if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
       continue;
      }
      if (ifr.ifr_hwaddr.sa_family != 1)
       continue;
      memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
      break;
#else
      if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_LINK)) {
        struct sockaddr_dl *s = (struct sockaddr_dl *)ifa->ifa_addr;
        if (memcmp(mac_null, s->sdl_data + s->sdl_nlen, 6)) {
          memcpy(mac, s->sdl_data + s->sdl_nlen, 6);
          break;
        }
      }
#endif
    }
    freeifaddrs(ifaddr);
  }
#if defined(__GNU__)
  close(sock);
#endif
#else
  /* GetAdaptersInfo is not part of the UWP (WINAPI_FAMILY_APP) API surface
   * and llvm-mingw's UWP iphlpapi import library does not export it, causing
   * link failures of librist-dependent UWP apps. GetAdaptersAddresses is
   * supported on both classic Win32 desktop and on UWP since Windows 8, so
   * use it unconditionally. */
  ULONG buf_size = 15 * 1024; /* MSDN-recommended initial size */
  PIP_ADAPTER_ADDRESSES adapters = NULL;
  ULONG ret = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 3 && ret == ERROR_BUFFER_OVERFLOW; attempt++) {
    free(adapters);
    adapters = (PIP_ADAPTER_ADDRESSES)malloc(buf_size);
    if (!adapters)
      return -1;
    ret = GetAdaptersAddresses(AF_UNSPEC,
                               GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
                               GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                               NULL, adapters, &buf_size);
  }
  if (ret != ERROR_SUCCESS) {
    free(adapters);
    return -1;
  }
  for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter != NULL;
       adapter = adapter->Next) {
    if (adapter->PhysicalAddressLength >= 6 &&
        memcmp(mac_null, adapter->PhysicalAddress, 6) != 0) {
      memcpy(mac, adapter->PhysicalAddress, 6);
      break;
    }
  }
  free(adapters);
#endif
  return 0;
}
#endif /* !__EMSCRIPTEN__ */
