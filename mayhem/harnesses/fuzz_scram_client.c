/*
 * The client side of SCRAM-SHA-256 that pgagroal runs against a PostgreSQL backend
 * (pgagroal_scram_client_auth) and against a remote pgagroal management port
 * (pgagroal_remote_management_scram_sha256). The input is everything the server sends:
 * AuthenticationSASL / SASLContinue (salt, iteration count, nonce) / SASLFinal (signature).
 * First byte selects the function.
 */
#include "fuzz_proto_setup.h"
#include <security.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   struct fuzz_peer peer;
   char username[] = "myuser";
   char password[] = "secret";
   int fd;

   if (size < 1)
   {
      return -1;
   }
   fuzz_proto_setup();
   fd = fuzz_peer_start(&peer, data + 1, size - 1);
   if (data[0] & 1)
   {
      SSL* s_ssl = NULL;
      (void)pgagroal_remote_management_scram_sha256(username, password, fd, &s_ssl);
   }
   else
   {
      struct message* response = NULL;
      if (pgagroal_scram_client_auth(username, password, fd, NULL, &response) == 0)
      {
         pgagroal_free_message(response);
      }
   }
   fuzz_peer_finish(&peer);
   return 0;
}
