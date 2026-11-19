/* pgagroal JSON parser (json.c / value.c / art.c / deque.c): parse, clone, serialise. */
#include "fuzz_common.h"
#include <json.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   struct json* obj = NULL;
   struct json* copy = NULL;
   char* str;

   fuzz_init_shmem();
   /* pgagroal_json_parse_string takes a NUL-terminated string (json.h). */
   str = malloc(size + 1);
   memcpy(str, data, size);
   str[size] = '\0';

   if (pgagroal_json_parse_string(str, &obj) == 0 && obj != NULL)
   {
      char* a = pgagroal_json_to_string(obj, FORMAT_JSON, NULL, 0);
      char* b = pgagroal_json_to_string(obj, FORMAT_TEXT, NULL, 0);
      char* c = pgagroal_json_to_string(obj, FORMAT_JSON_COMPACT, NULL, 0);
      if (pgagroal_json_clone(obj, &copy) == 0 && copy != NULL)
      {
         char* d = pgagroal_json_to_string(copy, FORMAT_JSON, NULL, 0);
         free(d);
         pgagroal_json_destroy(copy);
      }
      free(a);
      free(b);
      free(c);
   }
   pgagroal_json_destroy(obj);
   free(str);
   return 0;
}
