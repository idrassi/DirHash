

#pragma once


#ifdef _MSC_VER

typedef __int8 int8;
typedef __int16 int16;
typedef __int32 int32;
typedef unsigned __int8 byte;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;
typedef unsigned __int64	TC_LARGEST_COMPILER_UINT;
typedef __int64 int64;
typedef unsigned __int64 uint64;
#define LL(x) x##ui64

#pragma warning( disable : 4201 )  // disable: 4201 nonstandard extension used : nameless struct/union
#pragma warning( disable : 4324 )  // disable: 4324 structure was padded due to __declspec(align())

#else // !_MSC_VER

#include <inttypes.h>
#include <limits.h>
#include <memory.h>

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t byte;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

#define LL(x) x##ULL

#if UCHAR_MAX != 0xffU
#error UCHAR_MAX != 0xff
#endif
#define __int8 char

#if USHRT_MAX != 0xffffU
#error USHRT_MAX != 0xffff
#endif
#define __int16 short

#if UINT_MAX != 0xffffffffU
#error UINT_MAX != 0xffffffff
#endif
#define __int32 int

typedef uint64 TC_LARGEST_COMPILER_UINT;

#define BOOL int
#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#endif // !_MSC_VER

// Integer types required by Cryptolib
typedef unsigned __int8 uint_8t;
typedef unsigned __int16 uint_16t;
typedef unsigned __int32 uint_32t;
typedef uint64 uint_64t;

typedef union
{
	struct
	{
		unsigned __int32 LowPart;
		unsigned __int32 HighPart;
	};
	uint64 Value;

} UINT64_STRUCT;

#ifndef __has_builtin       // Optional of course
#define __has_builtin(x) 0  // Compatibility with non-clang compilers
#endif

