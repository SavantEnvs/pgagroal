/* Fixed daemon configuration shared by the wire-protocol harnesses: HBA rules loaded through
 * pgagroal's own HBA reader, one backend on a closed loopback port, one admin. Built once and only
 * read by the fuzzed code. */
#ifndef PGAGROAL_FUZZ_PROTO_SETUP_H
#define PGAGROAL_FUZZ_PROTO_SETUP_H

#include "fuzz_common.h"

static void
fuzz_proto_setup(void)
{
   static int done = 0;
   static const char hba[] =
      "host    all      all      127.0.0.1/32   all\n"
      "host    admin    admin    127.0.0.0/8    scram-sha-256\n"
      "host    mydb     myuser   10.0.0.0/8     md5\n"
      "host    rejectdb all      127.0.0.1/32   reject\n"
      "host    all      all      ::1/128        trust\n";
   struct main_configuration* config;
   char* path;

   if (done)
   {
      return;
   }
   done = 1;
   fuzz_init_shmem();
   fuzz_init_master_key();
   config = (struct main_configuration*)shmem;

   path = fuzz_write_temp((const uint8_t*)hba, sizeof(hba) - 1);
   if (pgagroal_read_hba_configuration(shmem, path) != 0)
   {
      fprintf(stderr, "fuzz: cannot load the built-in HBA rules\n");
      abort();
   }
   unlink(path);
   free(path);

   snprintf(config->servers[0].name, sizeof(config->servers[0].name), "primary");
   snprintf(config->servers[0].host, sizeof(config->servers[0].host), "127.0.0.1");
   config->servers[0].port = 1; /* closed: a connect fails at once */
   config->number_of_servers = 1;

   snprintf(config->admins[0].username, sizeof(config->admins[0].username), "admin");
   snprintf(config->admins[0].password, sizeof(config->admins[0].password), "adminpass");
   config->number_of_admins = 1;

   snprintf(config->users[0].username, sizeof(config->users[0].username), "myuser");
   snprintf(config->users[0].password, sizeof(config->users[0].password), "secret");
   config->number_of_users = 1;
   config->max_connections = 10;
}

#endif
