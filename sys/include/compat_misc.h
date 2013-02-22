/*
 * This file defines various functions and constants that are not properly defined in RIOT yet
 * TODO: move those functions and defines to their appropriate place in RIOT
 */

typedef unsigned int sa_family_t;
typedef int socklen_t;

#define INET_ADDRSTRLEN		(16)
#define INET6_ADDRSTRLEN	(48)

inline int getpagesize(void) {
	return 512;	// TODO: find appropriate pagesize
}
