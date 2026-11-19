/*
 * pgagroal_authenticate (security.c): what a client sends a pgagroal listener first —
 * cancel / GSS / SSL requests and the startup packet (pgagroal_read_timeout_message,
 * pgagroal_get_request, pgagroal_extract_username_database), then the HBA decision
 * (is_allowed -> pgagroal_is_allowed_address) for the fixed client address 127.0.0.1.
 *
 * The daemon is configured in "gracefully" mode, so an allowed client is refused right
 * before pgagroal_get_connection(): the pool code mutates shared connection state and
 * would make one input's result depend on earlier ones.
 */
#include "fuzz_proto_setup.h"
#include <security.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   struct fuzz_peer peer;
   int slot = -1;
   SSL* c_ssl = NULL;
   SSL* s_ssl = NULL;
   char address[] = "127.0.0.1";
   int fd;

   fuzz_proto_setup();
   ((struct main_configuration*)shmem)->gracefully = true;

   fd = fuzz_peer_start(&peer, data, size);
   (void)pgagroal_authenticate(fd, address, &slot, &c_ssl, &s_ssl);
   fuzz_peer_finish(&peer);
   return 0;
}
