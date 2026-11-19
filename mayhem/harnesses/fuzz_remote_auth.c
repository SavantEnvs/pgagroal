/*
 * pgagroal_remote_management_auth (security.c): the remote-admin login a client performs
 * against pgagroal's management port — SSL request, startup packet, admin database / HBA
 * check, then the server side of SCRAM-SHA-256 (client-first and client-final parsing,
 * nonce / proof / channel-binding base64). The input is the client's whole byte stream.
 */
#include "fuzz_proto_setup.h"
#include <security.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   struct fuzz_peer peer;
   SSL* c_ssl = NULL;
   char address[] = "127.0.0.1";
   int fd;

   fuzz_proto_setup();
   fd = fuzz_peer_start(&peer, data, size);
   (void)pgagroal_remote_management_auth(fd, address, &c_ssl);
   fuzz_peer_finish(&peer);
   return 0;
}
