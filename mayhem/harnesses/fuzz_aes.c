/* pgagroal AES envelope decoding (aes.c) + base64 (utils.c): the paths that decode
 * management payloads (pgagroal_decrypt_buffer with the master key) and user files
 * (base64 then pgagroal_decrypt with the master key). First byte selects the mode/path. */
#include "fuzz_common.h"
#include <security.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   static const int modes[] = {ENCRYPTION_AES_256_GCM, ENCRYPTION_AES_192_GCM, ENCRYPTION_AES_128_GCM};
   unsigned char* dec = NULL;
   size_t dec_size = 0;
   char* master = NULL;
   int mode;

   if (size < 1)
   {
      return -1;
   }
   fuzz_init_shmem();
   fuzz_init_master_key();
   mode = modes[(data[0] & 0x7f) % 3];

   if (data[0] & 0x80)
   {
      /* users-file path: base64 text -> pgagroal_decrypt(ciphertext, master key) */
      char* text = malloc(size);
      void* raw = NULL;
      size_t raw_len = 0;
      memcpy(text, data + 1, size - 1);
      text[size - 1] = '\0';
      if (pgagroal_base64_decode(text, strlen(text), &raw, &raw_len) == 0 && raw != NULL)
      {
         if (pgagroal_get_master_key(&master) == 0)
         {
            char* plain = NULL;
            pgagroal_decrypt((char*)raw, (int)raw_len, master, &plain, mode);
            free(plain);
         }
      }
      free(raw);
      free(text);
   }
   else
   {
      unsigned char* buf = malloc(size);
      memcpy(buf, data + 1, size - 1);
      pgagroal_decrypt_buffer(buf, size - 1, &dec, &dec_size, mode);
      free(dec);
      free(buf);
   }
   free(master);
   return 0;
}
