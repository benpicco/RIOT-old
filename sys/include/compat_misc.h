/*
 * This file defines various functions and constants that are not properly defined in RIOT yet
 * TODO: move those functions and defines to their appropriate place in RIOT
 */

typedef unsigned int sa_family_t;
typedef int socklen_t;

// since we only support v6…
#define sockaddr_in		socka6
#define sockaddr_in6		socka6
#define sockaddr		socka6
#define sockaddr_storage	socka6 

#define sa_family	sin6_family
#define sin_port	sin6_port
#define sin_addr	sin6_addr

#define htons HTONS
#define htonl HTONL
#define ntohs NTOHS
#define ntohl NTOHL

#define INET_ADDRSTRLEN		(16)
#define INET6_ADDRSTRLEN	(48)

inline int getpagesize(void) {
	return 512;	// TODO: find appropriate pagesize
}

#define IF_NAMESIZE 4
// dummy implementation, we don't have interface names
inline char* if_indextoname(unsigned int ifindex, char *ifname) {
	ifname[0] = 'i';
	ifname[1] = 'f';
	ifname[2] = ifindex + '0';
	ifname[3] = 0;

	return ifname;
}
