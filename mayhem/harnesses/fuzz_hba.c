/* pgagroal_hba.conf reader + validator (configuration.c: extract_hba) and the CIDR/netmask
 * matcher pgagroal_is_allowed_address (security.c). Input: the first line is a client address,
 * the rest is the HBA file; every loaded entry is matched against the address. */
#include "fuzz_common.h"
#include <security.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   struct main_configuration* config;
   const uint8_t* nl = memchr(data, '\n', size);
   size_t alen = nl ? (size_t)(nl - data) : size;
   char* address;
   char* path;

   fuzz_init_shmem();
   fuzz_reset_config();
   config = (struct main_configuration*)shmem;

   address = malloc(alen + 1);
   memcpy(address, data, alen);
   address[alen] = '\0';
   path = nl ? fuzz_write_temp(nl + 1, size - alen - 1) : fuzz_write_temp(data, 0);

   if (pgagroal_read_hba_configuration(shmem, path) == 0)
   {
      (void)pgagroal_validate_hba_configuration(shmem);
      for (int i = 0; i < config->number_of_hbas; i++)
      {
         (void)pgagroal_is_allowed_address(address, config->hbas[i].address);
      }
   }
   unlink(path);
   free(path);
   free(address);
   return 0;
}
