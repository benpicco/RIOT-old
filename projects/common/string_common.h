
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

#ifndef COMMON_STRING_H_
#define COMMON_STRING_H_

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include "common/common_types.h"

enum { STRARRAY_BLOCKSIZE = 64 };


/*
 * Represents a string or an array of strings
 * The strings (including there Zero-Byte) are just appended
 * into a large binary buffer. The struct contains a pointer
 * to the first string and the size of the binary buffer
 *
 * typically append operations are done by realloc() calls
 * while remove operations are done with memmove
 */
struct strarray {
  /* pointer to the first string */
  char *value;

  /* total length of all strings including zero-bytes */
  size_t length;
};

struct const_strarray {
  const char *value;

  const size_t length;
};

struct human_readable_str{
    char buf[48];
};

EXPORT char *strscpy (char *dest, const char *src, size_t size);
EXPORT char *strscat (char *dest, const char *src, size_t size);
EXPORT char *str_trim (char *ptr);
EXPORT const char *str_hasnextword (const char *buffer, const char *word);
EXPORT const char *str_cpynextword (char *dst, const char *buffer, size_t len);

EXPORT const char *str_get_human_readable_number(struct human_readable_str *out,
    uint64_t number, const char *unit, int maxfraction, bool binary, bool raw);

EXPORT bool str_is_printable(const char *value);

EXPORT int strarray_copy(struct strarray *dst, const struct strarray *src);
EXPORT int strarray_append(struct strarray *, const char *);
EXPORT int strarray_prepend(struct strarray *array, const char *string);
EXPORT void strarray_remove_ext(struct strarray *, char *, bool);

EXPORT char *strarray_get(const struct strarray *array, size_t idx);
EXPORT size_t strarray_get_count(const struct strarray *array);

EXPORT int strarray_cmp(const struct strarray *a1, const struct strarray *a2);

static INLINE bool
str_char_is_printable(char c) {
  unsigned char uc = (unsigned char) c;
  return !(uc < 32 || uc == 127 || uc == 255);
}

static INLINE int
strarray_copy_c(struct strarray *dst, const struct const_strarray *src) {
  return strarray_copy(dst, (const struct strarray *)src);
}

static INLINE const char *
strarray_get_c(const struct const_strarray *array, size_t idx) {
  return strarray_get((const struct strarray *)array, idx);
}

static INLINE size_t
strarray_get_count_c(const struct const_strarray *array) {
  return strarray_get_count((const struct strarray *)array);
}


/**
 * Initialize string array object
 * @param array pointer to string array object
 */
static INLINE void
strarray_init(struct strarray *array) {
  memset(array, 0, sizeof(*array));
}

/**
 * Free memory of string array object
 * @param array pointer to string array object
 */
static INLINE void
strarray_free(struct strarray *array) {
  free(array->value);
  strarray_init(array);
}

/**
 * @param array pointer to string array object
 * @return true if the array is empty, false otherwise
 */
static INLINE bool
strarray_is_empty(const struct strarray *array) {
  return array->value == NULL;
}

static INLINE bool
strarray_is_empty_c(const struct const_strarray *array) {
  return array->value == NULL;
}

/**
 * Remove an element from a string array
 * @param array pointer to string array object
 * @param element an element to be removed from the array
 */
static INLINE void
strarray_remove(struct strarray *array, char *element) {
  strarray_remove_ext(array, element, true);
}

/**
 * @param array pointer to strarray object
 * @return pointer to first string of string array
 */
static INLINE char *
strarray_get_first(const struct strarray *array) {
  return array->value;
}

static INLINE const char *
strarray_get_first_c(const struct const_strarray *array) {
  return array->value;
}

/**
 * Do not call this function for the last string in
 * a string array.
 * @param current pointer to a string in array
 * @return pointer to next string in string array
 */
static INLINE char *
strarray_get_next(char *current) {
  return current + strlen(current) + 1;
}

static INLINE const char *
strarray_get_next_c(const char *current) {
  return current + strlen(current) + 1;
}

/**
 * @param array pointer to strarray object
 * @param current pointer to a string in array
 * @return pointer to next string in string array,
 *   NULL if there is no further string
 */
static INLINE char *
strarray_get_next_safe(const struct strarray *array, char *current) {
  char *next;

  next = current + strlen(current) + 1;
  if (next > array->value + array->length) {
    return NULL;
  }
  return next;
}

static INLINE const char *
strarray_get_next_safe_c(const struct const_strarray *array,
    const char *current) {
  const char *next;

  next = current + strlen(current) + 1;
  if (next > array->value + array->length) {
    return NULL;
  }
  return next;
}

/**
 * Compare two constant stringarrays
 * @param a1 pointer to array 1
 * @param a2 pointer to array 2
 * @return <0 if a1 is 'smaller' than a2, >0 if a1 is 'larger' than a2,
 *   0 if both are the same.
 */
static INLINE int
strarray_cmp_c(const struct const_strarray *a1, const struct const_strarray *a2) {
  return strarray_cmp((const struct strarray *)a1, (const struct strarray *)a2);
}

/**
 * Loop over an array of strings. This loop should not be used if elements are
 * removed from the array during the loop.
 *
 * @param array pointer to strarray object
 * @param charptr pointer to loop variable
 */
#define FOR_ALL_STRINGS(array, charptr) for (charptr = (array)->value; charptr != NULL && charptr < (array)->value + (array)->length; charptr += strlen(charptr) + 1)

#endif
