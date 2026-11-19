# fuzz_management known findings

Upstream bugs reached through `pgagroal_management_read_json` (`src/libpgagroal/management.c`), the
function pgagroal and pgagroal-cli use to read every management request and reply. Each directory holds
an `input.bin` for `/mayhem/fuzz_management` (compression byte, encryption byte, a 4-byte big-endian
length, then the base64 payload). Replay one with `/mayhem/fuzz_management-standalone <dir>/input.bin`.

These inputs are kept out of `testsuite/` because Mayhem replays the seeds on every run. The seeds
`near_bzip2.bin`, `near_empty_payload.bin` and `near_gzip_truncated.bin` are each one byte (the
compression byte) away from the inputs here.

| Finding | Input | Cause | Fix |
|---|---|---|---|
| `read-json-error-double-free` | compression 3 (lz4), payload `!` (decodes to 0 bytes) | `pgagroal_lz4d_string`, `pgagroal_zstdd_string` and `pgagroal_bunzip2_string` `free(*output_string)` on failure but leave the pointer set; `read_json` stores it in `decompressed` and its `error:` path frees it again. Any corrupt lz4/zstd/bzip2 payload triggers it. | Set `*output_string = NULL` after each `free` in the codecs. |
| `bunzip2-empty-double-free` | compression 4 (bzip2), payload `!` | `compressed_size == 0` makes `estimated_size` 0; `BZ2_bzBuffToBuffDecompress` returns `BZ_OUTBUFF_FULL`, `realloc(p, 0)` frees `p` and returns NULL, and the failure branch (`bzip2_compression.c:96-101`) frees `p` again. | Reject `compressed_size == 0`, and do not free after a failed `realloc` of size 0. |
| `bzip2-unterminated-overread` | compression 4, a valid bzip2 stream of a JSON request | `pgagroal_bunzip2_string` never NUL-terminates its output; `pgagroal_json_parse_string` then `strlen`s past the heap buffer (`json.c:339`). | Allocate one more byte and write `output[estimated_size] = '\0'`. |
| `gunzip-truncated-hang` | compression 1 (gzip), the first 20 bytes of a gzip stream | `pgagroal_gunzip_string` loops `while (ret == Z_OK \|\| ret == Z_BUF_ERROR)`; once the input is used up, `inflate()` returns `Z_BUF_ERROR` forever, so one short request hangs the reader (remote DoS). | Stop when `ret == Z_BUF_ERROR && stream.avail_in == 0`. |
