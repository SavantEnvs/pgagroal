/* pgagroal.conf INI reader + validator (configuration.c): sections, key/value parsing,
 * as_int / as_bool / as_seconds / as_bytes conversions, server sections. The input is the
 * file. The configuration is reset to pgagroal's defaults before every input. */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   char* path;

   fuzz_init_shmem();
   fuzz_reset_config();
   path = fuzz_write_temp(data, size);
   if (pgagroal_read_configuration(shmem, path, false) == 0)
   {
      (void)pgagroal_validate_configuration(shmem, false, false);
   }
   unlink(path);
   free(path);
   return 0;
}
