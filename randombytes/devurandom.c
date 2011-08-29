/*
 * This file has been mashed up with random.c from the hashcash 1.22
 *  distribution, imported under its public domain license.  (The LICENSE
 *  file for hashcash identifies a number of license choices, we're picking
 *  public domain for simplicity.  Now we also include libsha1.c as well as
 *  sha1.h and random.h too.
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

#include <limits.h>

#define word unsigned

#define byte unsigned char 

#define bool byte
#define true 1
#define false 0

#define word8 unsigned char
#define int8 signed char

#define int16 signed short
#define word16 unsigned short

#if ( ULONG_MAX > 0xFFFFFFFFUL )
    #define int32 signed int
    #define word32 unsigned int
    #define int64 signed long
    #define word64 unsigned long
#elif ( UINT_MAX == 0xFFFFFFFFUL )
    #define int32 signed int
    #define word32 unsigned int
#else 
    #define int32 signed long
    #define word32 unsigned long
#endif

#if defined( __GNUC__ ) && !defined( word32 )
    #define int64 signed long long
    #define word64 unsigned long long
#endif

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

static int swap_endian32( void*, size_t );

/* A run time endian test.  

   little_endian is the broken one: 80x86s, VAXs
   big_endian is: most unix machines, RISC chips, 68000, etc

   The endianess is stored in macros:

         little_endian
   and   big_endian

   These boolean values can be checked in your code in C expressions.

   They should NOT be tested with conditional macro statements (#ifdef
   etc).
*/

static const int endian_test = 1;

#define little_endian ( *(char*)&endian_test == 1 )

#define big_endian ( ! little_endian )

#define make_big_endian32( data, len ) \
    ( little_endian ? swap_endian32( data, len ) : 0 )

#define make_little_endian32( data, len ) \
    ( little_endian ? 0 : swap_endian32( data, len ) )

#define make_local_endian32( data, len ) \
    ( little_endian ? swap_endian32( data, len ) : 0 )

#if defined( OPENSSL )

void SHA1_Xform( word32* iv, const byte* data ) {
    SHA1_ctx c;
    byte d[SHA1_INPUT_BYTES];

    c.h0=iv[0]; c.h1=iv[1]; c.h2=iv[2]; c.h3=iv[3]; c.h4=iv[4];

/* openSSL SHA1_Transform is in data order, trying to be helpful */
/* #undef SHA1_Transform */
/*    SHA1_Transform( &c, data ); */

    /* but they offer a host order version */
    /* but they don't export it :-( */
    /* sha1_block_asm_host_order( &c, data ); */

/* plan C, copy & convert the data on input */
#undef SHA1_Transform
    if ( little_endian ) { 
	memcpy( d, data, SHA1_INPUT_BYTES );
	make_local_endian32( d, SHA1_INPUT_WORDS );
	SHA1_Transform( &c, d );
    } else {			/* not necessary on big endian */
	SHA1_Transform( &c, data ); 
    }
    iv[0]=c.h0; iv[1]=c.h1; iv[2]=c.h2; iv[3]=c.h3; iv[4]=c.h4;
}

#else

#define min( x, y ) ( ( x ) < ( y ) ? ( x ) : ( y ) )

/********************* function used for rounds 0..19 ***********/

/* #define F1( B, C, D ) ( ( (B) & (C) ) | ( ~(B) & (D) ) ) */

/* equivalent, one less operation: */
#define F1( B, C, D ) ( (D) ^ ( (B) & ( (C) ^ (D) ) ) )


/********************* function used for rounds 20..39 ***********/

#define F2( B, C, D ) ( (B) ^ (C) ^ (D) )

/********************* function used for rounds 40..59 ***********/

/* #define F3( B, C, D ) ( (B) & (C) ) | ( (C) & (D) ) | ( (C) & (D) ) */

/* equivalent, one less operation */

#define F3( B, C, D ) ( ( (B) & ( (C) | (D) )) | ( (C) & (D) ) )

/********************* function used for rounds 60..79 ***********/

#define F4( B, C, D ) ( (B) ^ (C) ^ (D) )

#define K1 0x5A827999  /* constant used for rounds 0..19 */
#define K2 0x6ED9EBA1  /* constant used for rounds 20..39 */
#define K3 0x8F1BBCDC  /* constant used for rounds 40..59 */
#define K4 0xCA62C1D6  /* constant used for rounds 60..79 */

/* magic constants */

#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0

word32 SHA1_IV[ 5 ] = { H0, H1, H2, H3, H4 };

/* rotate X n bits left   ( X <<< n ) */

#define S(n, X) ( ( (X) << (n) ) | ( (X) >> ( 32 - (n) ) ) )

#if defined( word64 )
    #define SHA1_zero_bitcount( ctx )		\
        (ctx)->bits = 0;
#else
    #define SHA1_zero_bitcount( ctx )		\
    (ctx)->lbits = 0;				\
    (ctx)->hbits = 0;
#endif

void SHA1_Init( SHA1_ctx* ctx )
{
    SHA1_zero_bitcount( ctx );
    memcpy( ctx->H, SHA1_IV, SHA1_DIGEST_BYTES );
}

/* this is only used if you want to modify the IV */
/* ignore this function for purposes of the standard */

void SHA1_Init_With_IV( SHA1_ctx* ctx, 
			const byte user_IV[ SHA1_DIGEST_BYTES ] )
{
    SHA1_zero_bitcount( ctx );
    memcpy( ctx->H, user_IV, SHA1_DIGEST_BYTES );
    make_local_endian32( ctx->H, SHA1_DIGEST_WORDS );
}

void SHA1_Transform(  word32 H[ SHA1_DIGEST_WORDS ], 
		      const byte M[ SHA1_INPUT_BYTES ] )
{
#ifdef	COMPACT
    int t = 0 ;
#endif
    word32 A = H[ 0 ];
    word32 B = H[ 1 ];
    word32 C = H[ 2 ];
    word32 D = H[ 3 ];
    word32 E = H[ 4 ];
#if !defined( COMPACT )
    word32 W[ 16 ] = {0};
#else
    word32 W[ 80 ] = {0};
#endif

    memcpy( W, M, SHA1_INPUT_BYTES );

/* Use method B from FIPS-180 (see fip-180.txt) where the use of
   temporary array W of 80 word32s is avoided by working in a circular
   buffer of size 16 word32s.

   (Chromatix:  this is unreasonably slow on x86 due to register
    pressure - going back to method A)
*/

/********************* define some macros *********************/

/* Wc = access W as 16 word circular buffer */

#if !defined( COMPACT )
#define Wc( t ) ( W[ (t) & 0x0F ] )
#else
#define Wc( t ) ( W[ (t) ] )
#endif

/* Calculate access to W array on the fly for entries 16 .. 79 */

#if !defined( COMPACT )
#define Wf( t ) \
    ( Wc( t ) = S( 1, Wc( t ) ^ Wc( t - 14 ) ^ Wc( t - 8 ) ^ Wc( t - 3 ) ) )
#else
#define Wf( t ) \
    ( Wc( t ) = S( 1, Wc( t - 16 ) ^ Wc( t - 14 ) ^ Wc( t - 8 ) ^ Wc( t - 3 ) ) )
#endif

/* Calculate access to W virtual array calculating access to W on the fly */

#if !defined( COMPACT )
#define Wfly( t ) ( (t) < 16 ? Wc( (t) ) : Wf( (t) ) )
#else
#define Wfly( t ) ( Wc( (t) ) )
#endif

#if defined( VERBOSE )
#define REPORT( t, A, B, C, D, E ) \
    fprintf( stderr, "t = %2d: %08X   %08X   %08X   %08X   %08X\n",\
	     t, A, B, C, D, E );
#else
#define REPORT( t, A, B, C, D, E )
#endif

#define ROUND( t, A, B, C, D, E, Func, K ) \
    E += S( 5, A ) + Func( B, C, D ) + Wfly( t ) + K;\
    B = S( 30, B ); REPORT( t, E, A, B, C, D )

/* Remove rotatation E' = D; D' = C; C' = B; B' = A; A' = E; by
   completely unrolling and rotating the arguments to the macro ROUND
   manually so the rotation is compiled in.
*/

#define ROUND5( t, Func, K ) \
    ROUND( t + 0, A, B, C, D, E, Func, K );\
    ROUND( t + 1, E, A, B, C, D, Func, K );\
    ROUND( t + 2, D, E, A, B, C, Func, K );\
    ROUND( t + 3, C, D, E, A, B, Func, K );\
    ROUND( t + 4, B, C, D, E, A, Func, K )

#define ROUND20( t, Func, K )\
    ROUND5( t +  0, Func, K );\
    ROUND5( t +  5, Func, K );\
    ROUND5( t + 10, Func, K );\
    ROUND5( t + 15, Func, K )

/********************* use the macros *********************/

#if defined( VERBOSE ) && !defined( COMPACT )
    for ( t = 0; t < 16; t++ ) {
	fprintf( stderr, "W[%2d] = %08x\n", t, W[ t ] );
    }
    fprintf( stderr, 
"            A           B           C           D           E\n\n" );
#endif

#if defined( COMPACT )
/* initialise W buffer */
    for ( t = 16; t < 80; t++ ) {
        Wf( t );
    }
#endif

/* rounds  0..19 */

    ROUND20(  0, F1, K1 );

/* rounds 21..39 */

    ROUND20( 20, F2, K2 );

/* rounds 40..59 */

    ROUND20( 40, F3, K3 );

/* rounds 60..79 */

    ROUND20( 60, F4, K4 );
    
    H[ 0 ] += A;
    H[ 1 ] += B;
    H[ 2 ] += C;
    H[ 3 ] += D;
    H[ 4 ] += E;
}

void SHA1_Update( SHA1_ctx* ctx, const void* pdata, size_t data_len )
{
    const byte* data = (const byte*)pdata;
    unsigned use = 0 ;
    unsigned mlen = 0 ;
#if !defined( word64 )
    word32 low_bits = 0 ;
#endif

/* convert data_len to bits and add to the 64-bit bit count */

#if defined( word64 )
    mlen = (unsigned)( ( ctx->bits >> 3 ) % SHA1_INPUT_BYTES );
    ctx->bits += ( (word64) data_len ) << 3;
#else
    mlen = (unsigned)( ( ctx->lbits >> 3 ) % SHA1_INPUT_BYTES );
    ctx->hbits += data_len >> 29; /* simulate 64 bit addition */
    low_bits = data_len << 3;
    ctx->lbits += low_bits;
    if ( ctx->lbits < low_bits ) { ctx->hbits++; }
#endif

/* deal with first block */

    use = (unsigned)min( (size_t)(SHA1_INPUT_BYTES - mlen), data_len );
    memcpy( ctx->M + mlen, data, use );
    mlen += use;
    data_len -= use;
    data += use;

    while ( mlen == SHA1_INPUT_BYTES ) {
	make_big_endian32( (word32*)ctx->M, SHA1_INPUT_WORDS );
	SHA1_Transform( ctx->H, ctx->M );
	use = (unsigned)min( SHA1_INPUT_BYTES, data_len );
	memcpy( ctx->M, data, use );
	mlen = use;
	data_len -= use;
        data += use;
    }
}

void SHA1_Final( SHA1_ctx* ctx, byte digest[ SHA1_DIGEST_BYTES ] )
{
    unsigned mlen = 0 ;
    unsigned padding = 0 ;
#if defined( word64 )
    word64 temp = 0 ;
#endif

#if defined( word64 )
    mlen = (unsigned)(( ctx->bits >> 3 ) % SHA1_INPUT_BYTES);
#else
    mlen = (unsigned)(( ctx->lbits >> 3 ) % SHA1_INPUT_BYTES);
#endif

    ctx->M[ mlen ] = 0x80; mlen++; /* append a 1 bit */
    padding = SHA1_INPUT_BYTES - mlen;

#define BIT_COUNT_WORDS 2
#define BIT_COUNT_BYTES ( BIT_COUNT_WORDS * sizeof( word32 ) )

    if ( (unsigned)padding >= BIT_COUNT_BYTES ) {
	memset( ctx->M + mlen, 0x00, padding - BIT_COUNT_BYTES );
	make_big_endian32( ctx->M, SHA1_INPUT_WORDS - BIT_COUNT_WORDS );
    } else {
	memset( ctx->M + mlen, 0x00, SHA1_INPUT_BYTES - mlen );
	make_big_endian32( ctx->M, SHA1_INPUT_WORDS );
	SHA1_Transform( ctx->H, ctx->M );
	memset( ctx->M, 0x00, SHA1_INPUT_BYTES - BIT_COUNT_BYTES );
    }
    
#if defined( word64 )
    if ( little_endian ) {
	temp = ( ctx->bits << 32 | ctx->bits >> 32 );
    } else {
	temp = ctx->bits;
    }
    memcpy( ctx->M + SHA1_INPUT_BYTES - BIT_COUNT_BYTES, &temp, 
	    BIT_COUNT_BYTES );
#else
    memcpy( ctx->M + SHA1_INPUT_BYTES - BIT_COUNT_BYTES, &(ctx->hbits), 
	    BIT_COUNT_BYTES );
#endif
    SHA1_Transform( ctx->H, ctx->M );

    memcpy( digest, ctx->H, SHA1_DIGEST_BYTES );
    make_big_endian32( digest, SHA1_DIGEST_WORDS );
}

#endif

static int swap_endian32( void* data, size_t len )
{
    word32 tmp32 = 0 ;
    byte* tmp32_as_bytes = (byte*) &tmp32;
    word32* data_as_word32s = (word32*) data;
    byte* data_as_bytes = NULL ;
    size_t i = 0 ;
    
    for ( i = 0; i < len; i++ ) {
	tmp32 = data_as_word32s[ i ];
	data_as_bytes = (byte*) &( data_as_word32s[ i ] );
	
	data_as_bytes[ 0 ] = tmp32_as_bytes[ 3 ];
	data_as_bytes[ 1 ] = tmp32_as_bytes[ 2 ];
	data_as_bytes[ 2 ] = tmp32_as_bytes[ 1 ];
	data_as_bytes[ 3 ] = tmp32_as_bytes[ 0 ];
    }
    return 1;
}

#endif
