/* LP64 standalone port for the NetX Crypto library, used only by the Mayhem layer.

   The upstream Linux/GNU standalone port typedefs ULONG as `unsigned long`, which is 64 bits on
   x86-64. The huge-number code (RSA, ECC, DH) assumes a 32-bit ULONG, so its 64x64 products
   overflow and it computes wrong answers. This header keeps the ThreadX/ARM data model
   (32-bit ULONG, LONG) so the library behaves as it does on its real targets. */
#ifndef _NX_CRYPTO_PORT_H_
#define _NX_CRYPTO_PORT_H_

#include <stdlib.h>
#include <string.h>

#ifdef NX_CRYPTO_STANDALONE_ENABLE

#define NX_CRYPTO_LITTLE_ENDIAN 1

#define NX_CRYPTO_CHANGE_ULONG_ENDIAN(arg)       (arg) = __builtin_bswap32(arg)
#define NX_CRYPTO_CHANGE_USHORT_ENDIAN(arg)      (arg) = __builtin_bswap16(arg)

#ifndef VOID
#define VOID                                      void
typedef char                                      CHAR;
typedef unsigned char                             UCHAR;
typedef int                                       INT;
typedef unsigned int                              UINT;
typedef int                                       LONG;
typedef unsigned int                              ULONG;
typedef short                                     SHORT;
typedef unsigned short                            USHORT;
#endif

/* Pointer-sized, unlike ULONG here: the crypto sources use it to align scratch pointers. */
#define ALIGN_TYPE                                unsigned long

#endif /* NX_CRYPTO_STANDALONE_ENABLE */

#endif /* _NX_CRYPTO_PORT_H_ */
