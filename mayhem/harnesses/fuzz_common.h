/*
 * Shared setup for the pgagroal fuzz harnesses (mayhem/ layer, not upstream code).
 *
 * State kept across inputs, on purpose:
 *  - the shared-memory `struct main_configuration` (`shmem`): mapped once (it is large) and either
 *    wiped + re-initialised per input (config-file targets) or set up once and never written by the
 *    fuzzed code path (protocol targets: they only read config);
 *  - a fixed master key under a private $HOME (read-only after init), as upstream's test_aes.c does;
 *  - pgagroal's per-process message buffer (pgagroal_memory_init), which every read overwrites.
 */
#ifndef PGAGROAL_FUZZ_COMMON_H
#define PGAGROAL_FUZZ_COMMON_H

#include <pgagroal.h>
#include <aes.h>
#include <configuration.h>
#include <logging.h>
#include <memory.h>
#include <shmem.h>
#include <utils.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static size_t fuzz_shmem_size = 0;

static const char*
fuzz_tmpdir(void)
{
   const char* t = getenv("TMPDIR");
   return (t != NULL && *t != '\0') ? t : "/tmp";
}

/* Reset the configuration to pgagroal's defaults, with logging quiet (fatal only, console). */
static void
fuzz_reset_config(void)
{
   struct main_configuration* config;

   memset(shmem, 0, fuzz_shmem_size);
   pgagroal_init_configuration(shmem);
   config = (struct main_configuration*)shmem;
   config->common.log_type = PGAGROAL_LOGGING_TYPE_CONSOLE;
   config->common.log_level = PGAGROAL_LOGGING_LEVEL_FATAL;
   config->common.authentication_timeout = PGAGROAL_TIME_SEC(1);
}

static void
fuzz_init_shmem(void)
{
   if (shmem != NULL)
   {
      return;
   }
   signal(SIGPIPE, SIG_IGN);
   fuzz_shmem_size = sizeof(struct main_configuration);
   if (pgagroal_create_shared_memory(fuzz_shmem_size, HUGEPAGE_OFF, &shmem))
   {
      fprintf(stderr, "fuzz: pgagroal_create_shared_memory failed\n");
      abort();
   }
   fuzz_reset_config();
   pgagroal_memory_init();
}

/* A private $HOME holding .pgagroal/master.key (dir 0700, file 0600), the layout
 * pgagroal_get_master_key() requires. Same content as upstream's test_aes.c mock key. */
static void
fuzz_init_master_key(void)
{
   static int done = 0;
   static unsigned char salt[PBKDF2_SALT_LENGTH];
   char home[512];
   char path[600];
   char* enc_key = NULL;
   char* enc_salt = NULL;
   size_t l1 = 0, l2 = 0;
   FILE* f;

   if (done)
   {
      return;
   }
   done = 1;

   snprintf(home, sizeof(home), "%s/pgagroal-fuzz-home.XXXXXX", fuzz_tmpdir());
   if (mkdtemp(home) == NULL)
   {
      fprintf(stderr, "fuzz: mkdtemp %s: %s\n", home, strerror(errno));
      abort();
   }
   setenv("HOME", home, 1);
   snprintf(path, sizeof(path), "%s/.pgagroal", home);
   mkdir(path, 0700);
   chmod(path, 0700);
   snprintf(path, sizeof(path), "%s/.pgagroal/master.key", home);

   memset(salt, 0xAA, sizeof(salt));
   pgagroal_set_master_salt(salt);
   pgagroal_base64_encode("mock-master-key-str", strlen("mock-master-key-str"), &enc_key, &l1);
   pgagroal_base64_encode((char*)salt, PBKDF2_SALT_LENGTH, &enc_salt, &l2);
   f = fopen(path, "w");
   if (f == NULL || enc_key == NULL || enc_salt == NULL)
   {
      fprintf(stderr, "fuzz: cannot write %s\n", path);
      abort();
   }
   fprintf(f, "%s\n%s\n", enc_key, enc_salt);
   fclose(f);
   chmod(path, 0600);
   free(enc_key);
   free(enc_salt);
}

/* Write a buffer to a fresh temp file; returns a malloc'd path (caller unlinks + frees). */
static char*
fuzz_write_temp(const uint8_t* data, size_t size)
{
   char* path = malloc(512);
   int fd;

   snprintf(path, 512, "%s/pgagroal-fuzz.XXXXXX", fuzz_tmpdir());
   fd = mkstemp(path);
   if (fd < 0)
   {
      fprintf(stderr, "fuzz: mkstemp: %s\n", strerror(errno));
      abort();
   }
   size_t off = 0;
   while (off < size)
   {
      ssize_t w = write(fd, data + off, size - off);
      if (w <= 0)
      {
         abort();
      }
      off += (size_t)w;
   }
   close(fd);
   return path;
}

/*
 * Peer of a socketpair: sends the fuzz input (the remote side's whole byte stream), then
 * half-closes, and drains whatever pgagroal writes back so its writes never block.
 */
struct fuzz_peer
{
   int fd;
   const uint8_t* data;
   size_t size;
   pthread_t thread;
   int other;
};

static void*
fuzz_peer_main(void* arg)
{
   struct fuzz_peer* p = (struct fuzz_peer*)arg;
   size_t off = 0;
   int wr_open = 1;
   char sink[4096];

   if (p->size == 0)
   {
      shutdown(p->fd, SHUT_WR);
      wr_open = 0;
   }
   for (;;)
   {
      struct pollfd pfd = {.fd = p->fd, .events = POLLIN | (wr_open ? POLLOUT : 0)};
      if (poll(&pfd, 1, -1) < 0)
      {
         if (errno == EINTR)
         {
            continue;
         }
         break;
      }
      if (pfd.revents & POLLIN)
      {
         ssize_t r = recv(p->fd, sink, sizeof(sink), MSG_DONTWAIT);
         if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
         {
            break; /* pgagroal closed its end */
         }
      }
      if (wr_open && (pfd.revents & POLLOUT))
      {
         ssize_t w = send(p->fd, p->data + off, p->size - off, MSG_DONTWAIT | MSG_NOSIGNAL);
         if (w > 0)
         {
            off += (size_t)w;
         }
         else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
         {
            wr_open = 0;
         }
         if (off >= p->size)
         {
            shutdown(p->fd, SHUT_WR);
            wr_open = 0;
         }
      }
      if ((pfd.revents & (POLLHUP | POLLERR)) && !(pfd.revents & POLLIN))
      {
         break;
      }
   }
   return NULL;
}

/* Returns the fd to hand to pgagroal; fills *peer. */
static int
fuzz_peer_start(struct fuzz_peer* peer, const uint8_t* data, size_t size)
{
   int sv[2];

   if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
   {
      fprintf(stderr, "fuzz: socketpair: %s\n", strerror(errno));
      abort();
   }
   peer->fd = sv[0];
   peer->other = sv[1];
   peer->data = data;
   peer->size = size;
   if (pthread_create(&peer->thread, NULL, fuzz_peer_main, peer) != 0)
   {
      abort();
   }
   return sv[1];
}

/* pgagroal may already have closed its fd (pgagroal_disconnect on error paths). */
static void
fuzz_peer_finish(struct fuzz_peer* peer)
{
   if (fcntl(peer->other, F_GETFD) != -1)
   {
      shutdown(peer->other, SHUT_RDWR);
      close(peer->other);
   }
   else
   {
      shutdown(peer->fd, SHUT_RD);
   }
   pthread_join(peer->thread, NULL);
   close(peer->fd);
}

#endif
