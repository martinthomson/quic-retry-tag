# QUIC Retry Performance Test

A little test program for benchmarking options for protecting Retry.

In order to build this, you will need to have a copy of NSS in an adjacent
directory.  That needs to be built with `../nss/build.sh -o --static` (drop the
`-o` if you pass `DEBUG=true` to make).
