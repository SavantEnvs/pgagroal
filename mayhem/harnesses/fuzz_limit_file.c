/*
 * pgagroal_databases.conf reader + validator (configuration.c: extract_limit, aliases).
 * FILE-INPUT target (AFL, `afl: true`): pgagroal_read_limit_configuration calls exit(1) on
 * several invalid alias lines, exactly as the daemon does at start-up, so this is a
 * run-once program rather than a libFuzzer harness.
 * Usage: fuzz_limit_file <pgagroal_databases.conf>
 */
#include "fuzz_common.h"

int
main(int argc, char** argv)
{
   struct main_configuration* config;

   if (argc != 2)
   {
      fprintf(stderr, "usage: %s <pgagroal_databases.conf>\n", argv[0]);
      return 2;
   }
   fuzz_init_shmem();
   config = (struct main_configuration*)shmem;
   /* the limits are checked against the pool size, as with test/conf's pgagroal.conf */
   config->max_connections = 100;
   /* limit entries must name known users (pgagroal_validate_limit_configuration) */
   snprintf(config->users[0].username, sizeof(config->users[0].username), "myuser");
   snprintf(config->users[1].username, sizeof(config->users[1].username), "utf8user");
   config->number_of_users = 2;
   if (pgagroal_read_limit_configuration(shmem, argv[1]) == 0)
   {
      (void)pgagroal_validate_limit_configuration(shmem);
   }
   return 0;
}
