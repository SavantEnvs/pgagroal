/* pgagroal UTF-8 validation (utf8.c), used on user names and passwords. */
#include "fuzz_common.h"
#include <utf8.h>

int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
   size_t i = 0;

   (void)pgagroal_utf8_valid(data, size);
   while (i < size)
   {
      int n = pgagroal_utf8_char_length(data + i, size - i);
      int s = pgagroal_utf8_sequence_length(data[i]);
      if (s > 0 && (size_t)s <= size - i)
      {
         (void)pgagroal_utf8_sequence_valid(data + i, s);
      }
      i += (n > 0) ? (size_t)n : 1;
   }
   return 0;
}
