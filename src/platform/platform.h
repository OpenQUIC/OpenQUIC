#ifndef __OPENQUIC_PLATFORM_H__
#define __OPENQUIC_PLATFORM_H__

#include <stddef.h>
#include <sys/cdefs.h>

void *quic_malloc(const size_t size);
int quic_free(void *const ptr);

// define __quic_header_inline
#if defined(__APPLE__)
#define __quic_header_inline __header_always_inline
#elif defined(__linux__)
#define __quic_header_inline static inline
#endif

// define bswap_xx
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>

#define quic_bswap_16 OSSwapInt16
#define quic_bswap_32 OSSwapInt32
#define quic_bswap_64 OSSwapInt64
#elif defined(__linux__)
#include <byteswap.h>

#define quic_bswap_16 bswap_16
#define quic_bswap_32 bswap_32
#define quic_bswap_64 bswap_64
#endif

#endif
