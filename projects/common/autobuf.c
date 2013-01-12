
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004-2012, the olsr.org team - see HISTORY file
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#ifdef WIN32
#include <winsock2.h>
#endif

#include "common/autobuf.h"

static size_t AUTOBUFCHUNK = 0;

/**
 * @param val original size
 * @param pow2 power of 2 (1024, 4096, ...)
 * @return multiple of pow2 which larger or equal val
 */
static INLINE size_t
ROUND_UP_TO_POWER_OF_2(size_t val, size_t pow2) {
  return (val + pow2 - 1) & ~(pow2 - 1);
}

static int _autobuf_enlarge(struct autobuf *autobuf, size_t new_size);

/**
 * Initialize an autobuffer and allocate a chunk of memory
 * @param autobuf pointer to autobuf object
 * @return -1 if an out-of-memory error happened, 0 otherwise
 */
int
abuf_init(struct autobuf *autobuf)
{
  if (AUTOBUFCHUNK == 0) {
    AUTOBUFCHUNK = 512; //getpagesize();
  }

  autobuf->_len = 0;
  autobuf->_buf = calloc(1, AUTOBUFCHUNK);
  if (autobuf->_buf == NULL) {
    return -1;
  }
  autobuf->_total = AUTOBUFCHUNK;
  return 0;
}

/**
 * Free all currently used memory of an autobuffer.
 * The buffer can still be used afterwards !
 * @param autobuf pointer to autobuf object
 */
void
abuf_free(struct autobuf *autobuf)
{
  free(autobuf->_buf);
  memset(autobuf, 0, sizeof(*autobuf));
}

/**
 * vprintf()-style function that appends the output to an autobuffer
 * @param autobuf pointer to autobuf object
 * @param format printf format string
 * @param ap variable argument list pointer
 * @return -1 if an out-of-memory error happened,
 *   otherwise it returns the number of written characters
 *   (excluding the \0)
 */
int
abuf_vappendf(struct autobuf *autobuf,
    const char *format, va_list ap)
{
  int rc;
  size_t min_size;
  va_list ap2;

  if (autobuf == NULL) return 0;

  va_copy(ap2, ap);
  rc = vsnprintf(autobuf->_buf + autobuf->_len, autobuf->_total - autobuf->_len, format, ap);
  va_end(ap);
  min_size = autobuf->_len + (size_t)rc;
  if (min_size >= autobuf->_total) {
    if (_autobuf_enlarge(autobuf, min_size) < 0) {
      autobuf->_buf[autobuf->_len] = '\0';
      return -1;
    }
    vsnprintf(autobuf->_buf + autobuf->_len, autobuf->_total - autobuf->_len, format, ap2);
  }
  va_end(ap2);
  autobuf->_len = min_size;
  return rc;
}

/**
 * printf()-style function that appends the output to an autobuffer.
 * The function accepts a variable number of arguments based on the format string.
 * @param autobuf pointer to autobuf object
 * @param fmt printf format string
 * @return -1 if an out-of-memory error happened,
 *   otherwise it returns the number of written characters
 *   (excluding the \0)
 */
int
abuf_appendf(struct autobuf *autobuf, const char *fmt, ...)
{
  int rv;
  va_list ap;

  if (autobuf == NULL) return 0;

  va_start(ap, fmt);
  rv = abuf_vappendf(autobuf, fmt, ap);
  va_end(ap);
  return rv;
}

/**
 * Appends a null-terminated string to an autobuffer
 * @param autobuf pointer to autobuf object
 * @param s string to append to the buffer
 * @return -1 if an out-of-memory error happened,
 *   otherwise it returns the number of written characters
 *   (excluding the \0)
 */
int
abuf_puts(struct autobuf *autobuf, const char *s)
{
  size_t len;

  if (autobuf == NULL || s == NULL) return 0;

  len  = strlen(s);
  if (_autobuf_enlarge(autobuf, autobuf->_len + len + 1) < 0) {
    return -1;
  }
  strcpy(autobuf->_buf + autobuf->_len, s);
  autobuf->_len += len;
  return len;
}

/**
 * Appends a formatted time string to an autobuffer
 * @param autobuf pointer to autobuf object
 * @param format strftime() format string
 * @param tm pointer to time data
 * @return -1 if an out-of-memory error happened, 0 otherwise
 */
int
abuf_strftime(struct autobuf *autobuf, const char *format, const struct tm *tm)
{
  size_t rc;

  if (autobuf == NULL) return 0;

  rc = strftime(autobuf->_buf + autobuf->_len, autobuf->_total - autobuf->_len, format, tm);
  if (rc == 0) {
    /* we had an error! Probably the buffer too small. So we add some bytes. */
    if (_autobuf_enlarge(autobuf, autobuf->_total + AUTOBUFCHUNK) < 0) {
      autobuf->_buf[autobuf->_len] = '\0';
      return -1;
    }

    rc = strftime(autobuf->_buf + autobuf->_len, autobuf->_total - autobuf->_len, format, tm);
    if (rc == 0) {
      /* make sure we are null-terminated */
      autobuf->_buf[autobuf->_len + rc] = 0;

      return -1;
    }
  }

  /* add data to length field */
  autobuf->_len += rc;

  if (rc == 0) {
    return -1;
  }
  return rc;
}

/**
 * Copies a binary buffer to the end of an autobuffer.
 * @param autobuf pointer to autobuf object
 * @param p pointer to memory block to be copied
 * @param len length of memory block
 * @return -1 if an out-of-memory error happened, 0 otherwise
 */
int
abuf_memcpy(struct autobuf *autobuf, const void *p, const size_t len)
{
  if (autobuf == NULL || len == 0) return 0;

  if (_autobuf_enlarge(autobuf, autobuf->_len + len) < 0) {
    return -1;
  }
  memcpy(autobuf->_buf + autobuf->_len, p, len);
  autobuf->_len += len;

  /* null-terminate autobuf */
  autobuf->_buf[autobuf->_len] = 0;

  return 0;
}

/**
 * Append a memory block to the beginning of an autobuffer.
 * @param autobuf pointer to autobuf object
 * @param p pointer to memory block to be copied as a prefix
 * @param len length of memory block
 * @return -1 if an out-of-memory error happened, 0 otherwise
 */
int
abuf_memcpy_prepend(struct autobuf *autobuf,
    const void *p, const size_t len)
{
  if (autobuf == NULL || len == 0) return 0;

  if (_autobuf_enlarge(autobuf, autobuf->_len + len) < 0) {
    return -1;
  }
  memmove(&autobuf->_buf[len], autobuf->_buf, autobuf->_len);
  memcpy(autobuf->_buf, p, len);
  autobuf->_len += len;

  /* null-terminate autobuf */
  autobuf->_buf[autobuf->_len] = 0;

  return 0;
}

/**
 * Remove a prefix from an autobuffer. This function can be used
 * to create an autobuffer based fifo.
 * @param autobuf pointer to autobuf object
 * @param len number of bytes to be removed
 */
void
abuf_pull(struct autobuf * autobuf, size_t len) {
  char *p;
  size_t newsize;

  if (autobuf == NULL || len == 0) return;

  if (len != autobuf->_len) {
    memmove(autobuf->_buf, &autobuf->_buf[len], autobuf->_len - len);
  }
  autobuf->_len -= len;

  if (autobuf->_len + AUTOBUFCHUNK > autobuf->_total) {
    /* only reduce buffer size if difference is larger than a chunk */
    return;
  }
  newsize = autobuf->_total -= AUTOBUFCHUNK;
  if (newsize < AUTOBUFCHUNK) {
    newsize = AUTOBUFCHUNK;
  }

  /* generate smaller buffer */
  p = realloc(autobuf->_buf, newsize);
  if (p == NULL) {
    /* keep the longer buffer if we cannot get a smaller one */
    return;
  }
  autobuf->_buf = p;
  autobuf->_total = newsize;
  return;
}


/**
 * Enlarge an autobuffer if necessary
 * @param autobuf pointer to autobuf object
 * @param new_size number of bytes necessary in autobuffer
 * @return -1 if an out-of-memory error happened, 0 otherwise
 */
static int
_autobuf_enlarge(struct autobuf *autobuf, size_t new_size)
{
  char *p;
  size_t roundUpSize;

  new_size++;
  if (new_size > autobuf->_total) {
    roundUpSize = ROUND_UP_TO_POWER_OF_2(new_size+1, AUTOBUFCHUNK);
    p = realloc(autobuf->_buf, roundUpSize);
    if (p == NULL) {
#ifdef WIN32
      WSASetLastError(ENOMEM);
#else
      errno = ENOMEM;
#endif
      return -1;
    }
    autobuf->_buf = p;

    memset(&autobuf->_buf[autobuf->_total], 0, roundUpSize - autobuf->_total);
    autobuf->_total = roundUpSize;
  }
  return 0;
}
