/*
 * Backend-reply framing and field extraction, as pgagroal handles a PostgreSQL server's replies
 * during authentication (security.c): pgagroal_read_complete_message reads each typed message off
 * the socket (header length checks, split reads), then pgagroal_extract_message pulls the
 * ErrorResponse / Authentication / BackendKeyData message out of it and
 * pgagroal_extract_error_message walks the ErrorResponse fields. The input is the server's byte
 * stream; up to 16 messages are read.
 */
#include "fuzz_common.h"
#include <message.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   static const char kinds[] = {'E', 'R', 'K'};
   struct fuzz_peer peer;
   int fd;

   fuzz_init_shmem();
   fd = fuzz_peer_start(&peer, data, size);
   for (int n = 0; n < 16; n++)
   {
      struct message* msg = NULL; /* pgagroal's per-process buffer: not freed */
      if (pgagroal_read_complete_message(NULL, fd, &msg) != MESSAGE_STATUS_OK || msg == NULL)
      {
         break;
      }
      for (size_t k = 0; k < sizeof(kinds); k++)
      {
         struct message* extracted = NULL;
         if (pgagroal_extract_message(kinds[k], msg, &extracted) == 0 && extracted != NULL)
         {
            if (kinds[k] == 'E')
            {
               char* error = NULL;
               pgagroal_extract_error_message(extracted, &error);
               free(error);
            }
            pgagroal_free_message(extracted);
         }
      }
   }
   fuzz_peer_finish(&peer);
   return 0;
}
