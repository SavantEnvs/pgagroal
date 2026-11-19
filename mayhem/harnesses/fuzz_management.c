/*
 * pgagroal_management_read_json (management.c): how pgagroal and pgagroal-cli read every
 * management request / reply — compression byte, encryption byte, length-prefixed string,
 * then base64 -> AES-GCM (master key) -> gzip/zstd/lz4/bzip2 -> JSON parse.
 * The input is the peer's byte stream.
 * The seeds cover every codec; near_*.bin carry compression NONE in front of a bzip2, empty or
 * truncated-gzip payload, one byte away from the upstream bugs in mayhem/fuzz_management/known-findings/.
 * Throughput is bounded by upstream itself: read_string mallocs + memsets the peer's 32-bit length
 * (up to the 2 GB malloc limit), and an encrypted payload with a non-master salt runs PBKDF2
 * (600000 iterations, aes.h) per input.
 */
#include "fuzz_common.h"
#include <json.h>
#include <management.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   struct fuzz_peer peer;
   struct json* json = NULL;
   uint8_t compression = 0;
   uint8_t encryption = 0;
   int fd;

   fuzz_init_shmem();
   fuzz_init_master_key();
   fd = fuzz_peer_start(&peer, data, size);
   if (pgagroal_management_read_json(NULL, fd, &compression, &encryption, &json) == 0 && json != NULL)
   {
      char* s = pgagroal_json_to_string(json, FORMAT_JSON, NULL, 0);
      free(s);
   }
   pgagroal_json_destroy(json);
   fuzz_peer_finish(&peer);
   return 0;
}
