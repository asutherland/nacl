/*
 * This file has been mashed up with random.c from the hashcash 1.22
 *  distribution, imported under its public domain license.  (The LICENSE
 *  file for hashcash identifies a number of license choices, we're picking
 *  public domain for simplicity.
 */

/* on machines that have /dev/urandom -- use it */

#if defined( __linux__ ) || defined( __FreeBSD__ ) || defined( __MACH__ ) || \
    defined( __OpenBSD__ ) || defined( DEV_URANDOM )

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* it's really stupid that there isn't a syscall for this */

static int fd = -1;

void randombytes(unsigned char *x,unsigned long long xlen)
{
  int i;

  if (fd == -1) {
    for (;;) {
      fd = open("/dev/urandom",O_RDONLY);
      if (fd != -1) break;
      sleep(1);
    }
  }

  while (xlen > 0) {
    if (xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

#else

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <sys/time.h>

/* if no /dev/urandom fall back to a crappy rng who's only
 * entropy source is your high resolution timer
 */

/* on windows we are ok as we can use CAPI, but use CAPI combined with
   the below just to be sure! */

/* WARNING: on platforms other than windows this is not of
 * cryptographic quality 
 */

#include <stdlib.h>

#if defined( unix ) || defined( VMS )
    #include <unistd.h>
    #include <sys/time.h>
#elif defined( WIN32 )
    #include <process.h>
    #include <windows.h>
    #include <wincrypt.h>
    #include <sys/time.h>
#else
    #include <time.h>
#endif
#include <time.h>
#if defined( OPENSSL )
    #include <openssl/sha.h>
    #define SHA1_ctx SHA_CTX
    #define SHA1_Final( x, digest ) SHA1_Final( digest, x )
    #define SHA1_DIGEST_BYTES SHA_DIGEST_LENGTH
#else
/* for size_t */
#include <string.h>
#include "types.h"

#if defined( __cplusplus )
extern "C" {
#endif

#define SHA1_INPUT_BYTES 64	/* 512 bits */
#define SHA1_INPUT_WORDS ( SHA1_INPUT_BYTES >> 2 )
#define SHA1_DIGEST_WORDS 5	/* 160 bits */
#define SHA1_DIGEST_BYTES ( SHA1_DIGEST_WORDS * 4 )

#if defined( OPENSSL )

#include <openssl/sha.h>
#define SHA1_ctx SHA_CTX
#define SHA1_Final( ctx, digest ) SHA1_Final( digest, ctx )
#undef SHA1_DIGEST_BYTES
#define SHA1_DIGEST_BYTES SHA_DIGEST_LENGTH

#define SHA1_Init_With_IV( ctx, iv )		\
    do {					\
        (ctx)->h0 = iv[0];			\
        (ctx)->h1 = iv[1];			\
        (ctx)->h2 = iv[2];			\
        (ctx)->h3 = iv[3];			\
        (ctx)->h4 = iv[4];			\
        (ctx)->Nh = 0;				\
        (ctx)->Nl = 0;				\
        (ctx)->num = 0l				\
    } while (0)

#define SHA1_Transform( iv, data ) SHA1_Xform( iv, data )

#else

typedef struct {
    word32 H[ SHA1_DIGEST_WORDS ];
#if defined( word64 )
    word64 bits;		/* we want a 64 bit word */
#else
    word32 hbits, lbits;	/* if we don't have one we simulate it */
#endif
    byte M[ SHA1_INPUT_BYTES ];
} SHA1_ctx;

void SHA1_Init  ( SHA1_ctx* );
void SHA1_Update( SHA1_ctx*, const void*, size_t );
void SHA1_Final ( SHA1_ctx*, byte[ SHA1_DIGEST_BYTES ] );

/* these provide extra access to internals of SHA1 for MDC and MACs */

void SHA1_Init_With_IV( SHA1_ctx*, const byte[ SHA1_DIGEST_BYTES ] );

#endif

void SHA1_Xform( word32[ SHA1_DIGEST_WORDS ], 
		 const byte[ SHA1_INPUT_BYTES ] );

#if defined( __cplusplus )
}
#endif
#endif

#if defined( WIN32 )
    #define pid_t int
    typedef BOOL (WINAPI *CRYPTACQUIRECONTEXT)(HCRYPTPROV *, LPCTSTR, LPCTSTR,
					       DWORD, DWORD);
    typedef BOOL (WINAPI *CRYPTGENRANDOM)(HCRYPTPROV, DWORD, BYTE *);
    typedef BOOL (WINAPI *CRYPTRELEASECONTEXT)(HCRYPTPROV, DWORD);
    HCRYPTPROV hProvider = 0;
    CRYPTRELEASECONTEXT release = 0;
    CRYPTGENRANDOM gen = 0;
#endif

byte state[ SHA1_DIGEST_BYTES ];
byte output[ SHA1_DIGEST_BYTES ];
long counter = 0;

/* output = SHA1( input || time || pid || counter++ ) */

static void random_stir( const byte input[SHA1_DIGEST_BYTES],
			 byte output[SHA1_DIGEST_BYTES] )
{
    SHA1_ctx sha1;
#if defined(__unix__) || defined(WIN32)
    pid_t pid = getpid();
#else
    unsigned long pid = rand();
#endif
#if defined(__unix__)
    struct timeval tv = {};
    struct timezone tz = {};
#endif
#if defined(WIN32)
    SYSTEMTIME tw;
    BYTE buf[64];
#endif
    clock_t t = clock();
    time_t t2 = time(0);

    SHA1_Init( &sha1 );
#if defined(__unix__)
    gettimeofday(&tv,&tz);
    SHA1_Update( &sha1, &tv, sizeof( tv ) );
    SHA1_Update( &sha1, &tz, sizeof( tz ) );
#endif
#if defined(WIN32)
    GetSystemTime(&tw);
    SHA1_Update( &sha1, &tw, sizeof( tw ) );    
    if ( gen ) {
	if (gen(hProvider, sizeof(buf), buf)) {
	    SHA1_Update( &sha1, buf, sizeof(buf) );
	}
    }
#endif
    SHA1_Update( &sha1, input, SHA1_DIGEST_BYTES );
    SHA1_Update( &sha1, &t, sizeof( clock_t ) );
    SHA1_Update( &sha1, &t2, sizeof( time_t ) );
    SHA1_Update( &sha1, &pid, sizeof( pid ) );
    SHA1_Update( &sha1, &counter, sizeof( long ) );

    SHA1_Final( &sha1, output );
    counter++;
}

static int initialized = 0;

int random_init( void )
{
#if defined(WIN32)
    HMODULE advapi = 0;
    CRYPTACQUIRECONTEXT acquire = 0;
#endif

#if defined(WIN32)
    advapi = LoadLibrary(TEXT("ADVAPI32.DLL"));
    if (advapi) {
	acquire = (CRYPTACQUIRECONTEXT) 
	    GetProcAddress(advapi, TEXT("CryptAcquireContextA"));
	gen = (CRYPTGENRANDOM) 
	    GetProcAddress(advapi, TEXT("CryptGenRandom"));
	release = (CRYPTRELEASECONTEXT)
	    GetProcAddress(advapi, TEXT("CryptReleaseContext"));
    }
    if ( acquire && gen ) {
	if (!acquire(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
	    gen = NULL;
	}
    }
#endif
    srand(clock());
    random_stir( state, state );
    
    initialized = 1;

    return 1;
}

int random_final( void )
{
#if defined(WIN32)
    if ( hProvider && release ) { release(hProvider,0); }
#endif
    return 1;
}

#define CHUNK_LEN (SHA1_DIGEST_BYTES)

int randombytes( unsigned char* rnd, unsigned long long len )
{
    byte* rndp = (byte*)rnd;
    int use = 0;

    if ( !initialized && !random_init() ) { return 0; }

    random_stir( state, state ); /* mix in the time, pid */
    for ( ; len > 0; len -= use, rndp += CHUNK_LEN ) {
	random_stir( state, output );
	use = len > CHUNK_LEN ? CHUNK_LEN : len;
	memcpy( rndp, output, use );
    }
    return 1;
}

#endif
