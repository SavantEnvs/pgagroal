/* The user-credential files (configuration.c): pgagroal_users.conf, pgagroal_frontend_users.conf,
 * pgagroal_admins.conf and pgagroal_superuser.conf — "user:base64(AES(password))" lines, decoded and
 * decrypted with the master key, then validated. First byte selects the file kind; the rest is the
 * file. The configuration is reset before every input. */
#include "fuzz_common.h"

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   char* path;

   if (size < 1)
   {
      return -1;
   }
   fuzz_init_shmem();
   fuzz_init_master_key();
   fuzz_reset_config();
   path = fuzz_write_temp(data + 1, size - 1);
   switch (data[0] % 4)
   {
      case 0:
         if (pgagroal_read_users_configuration(shmem, path) == 0)
         {
            (void)pgagroal_validate_users_configuration(shmem);
         }
         break;
      case 1:
         if (pgagroal_read_frontend_users_configuration(shmem, path) == 0)
         {
            (void)pgagroal_validate_frontend_users_configuration(shmem);
         }
         break;
      case 2:
         if (pgagroal_read_admins_configuration(shmem, path) == 0)
         {
            (void)pgagroal_validate_admins_configuration(shmem);
         }
         break;
      default:
         if (pgagroal_read_superuser_configuration(shmem, path) == 0)
         {
            (void)pgagroal_validate_superuser_configuration(shmem);
         }
         break;
   }
   unlink(path);
   free(path);
   return 0;
}
