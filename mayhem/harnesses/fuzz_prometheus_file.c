/*
 * pgagroal_prometheus (prometheus.c): the HTTP handler behind the metrics port — request
 * line parsing (resolve_page) and the home / metrics / unknown / bad-request pages built
 * from the pool state. FILE-INPUT target (AFL, `afl: true`): pgagroal runs this in a forked
 * child and it always ends in exit(), so it cannot be a libFuzzer harness. The file's bytes
 * are delivered as the HTTP client's request over a socketpair.
 * Usage: fuzz_prometheus_file <request>
 */
#include "fuzz_common.h"
#include <prometheus.h>

int
main(int argc, char** argv)
{
   struct main_configuration* config;
   struct fuzz_peer peer;
   size_t psize = 0, csize = 0, len = 0, cap = 4096;
   uint8_t* buf;
   FILE* f;
   int fd;

   if (argc != 2)
   {
      fprintf(stderr, "usage: %s <request>\n", argv[0]);
      return 2;
   }
   f = fopen(argv[1], "rb");
   if (f == NULL)
   {
      perror(argv[1]);
      return 2;
   }
   buf = malloc(cap);
   for (;;)
   {
      size_t r = fread(buf + len, 1, cap - len, f);
      len += r;
      if (r == 0)
      {
         break;
      }
      if (len == cap)
      {
         cap *= 2;
         buf = realloc(buf, cap);
      }
   }
   fclose(f);

   fuzz_init_shmem();
   config = (struct main_configuration*)shmem;
   config->common.metrics = 9187;
   snprintf(config->common.host, sizeof(config->common.host), "localhost");
   snprintf(config->servers[0].name, sizeof(config->servers[0].name), "primary");
   snprintf(config->servers[0].host, sizeof(config->servers[0].host), "127.0.0.1");
   config->servers[0].port = 1;
   config->number_of_servers = 1;
   config->max_connections = 10;
   if (pgagroal_init_prometheus(&psize, &prometheus_shmem) ||
       pgagroal_init_prometheus_cache(&csize, &prometheus_cache_shmem))
   {
      fprintf(stderr, "prometheus init failed\n");
      return 2;
   }

   fd = fuzz_peer_start(&peer, buf, len);
   pgagroal_prometheus(NULL, fd); /* exits */
   return 0;
}
