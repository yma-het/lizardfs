/*
   Copyright 2005-2010 Jakub Kruszona-Zawadzki, Gemius SA, 2013 Skytechnology sp. z o.o..

   This file was part of MooseFS and is part of LizardFS.

   LizardFS is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, version 3.

   LizardFS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LizardFS  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common/platform.h"
#include "common/sockets.h"
#include "common/slogger.h"
#include "common/exceptions.h"
#include "common/cwrap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

/* Acid's simple socket library - ver 2.0 */

/* ---------------SOCK ADDR--------------- */

static inline int sockaddrnumfill(struct sockaddr_in6 *sa, struct in6_addr ip,uint16_t port) {
	memset(sa,0,sizeof(struct sockaddr_in));
	sa->sin6_family = AF_UNSPEC;
	sa->sin6_port = htons(port);
        memcpy(sa->sin6_addr.s6_addr, &ip, sizeof ip);
	//sa->sin6_addr.s6_addr = htonl(ip);
	return 0;
}

static inline int sockaddrfill(struct sockaddr_in6 *sa,const char *hostname,const char *service,int family,int socktype,int passive) {
	struct addrinfo hints, *res, *reshead;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
        lzfs_pretty_syslog(LOG_WARNING,"stage1");
	hints.ai_socktype = socktype;
	if (passive) {
		hints.ai_flags = AI_PASSIVE;
	}
	if (hostname && hostname[0]=='*') {
		hostname=NULL;
	}
	if (service && service[0]=='*') {
		service=NULL;
	}
        lzfs_pretty_syslog(LOG_WARNING,"stage2");
	if (getaddrinfo(hostname,service,&hints,&reshead)) {
                lzfs_pretty_syslog(LOG_WARNING,"hostname = %s service = %s", hostname, service);
		return -1;
                lzfs_pretty_syslog(LOG_WARNING,"stage?");
	}
	for (res = reshead ; res ; res=res->ai_next) {
		if (res->ai_family==family && res->ai_socktype==socktype && res->ai_addrlen==sizeof(struct sockaddr_in6)) {
			//*sa = *((struct sockaddr_in*)(res->ai_addr));
                        memcpy(sa, res->ai_addr, res->ai_addrlen);
			freeaddrinfo(reshead);
                        lzfs_pretty_syslog(LOG_WARNING,"succeded!");
			return 0;
		}
	}
        lzfs_pretty_syslog(LOG_WARNING,"exiting hungry(");
	freeaddrinfo(reshead);
	return -1;
}

static inline int sockresolve(const char *hostname,const char *service,struct in6_addr *ip,uint16_t *port,int family,int socktype,int passive) {
	struct sockaddr_in6 sa;

        lzfs_pretty_syslog(LOG_WARNING,"hostname = %s", hostname);
        lzfs_pretty_syslog(LOG_WARNING,"service = %s", service);
        /*struct in_addr ip_addr;
        ip_addr.s_addr = ntohl(sa.sin_addr.s_addr);
        lzfs_pretty_syslog(LOG_WARNING,"ip = %s", inet_ntoa(ip_addr));
        lzfs_pretty_syslog(LOG_WARNING,"port = %" PRIu16 "", ntohs(sa.sin_port)); //warning: format ‘%u’ expects argument of type ‘unsigned int’, but argument 3 has type ‘uint16_t* {aka short unsigned int*}’ [-Wformat=]
        lzfs_pretty_syslog(LOG_WARNING,"family = %d", family);
        lzfs_pretty_syslog(LOG_WARNING,"socktype = %d", socktype);
        lzfs_pretty_syslog(LOG_WARNING,"passive = %d", passive);*/

        /*printf("hostname = %s\n", hostname);
        printf("service = %s\n", service);
        printf("ip = %" PRIu32 "\n", ip);
        printf("port = %" PRIu16 "\n", port);
        printf("family = %d\n", family);
        printf("socktype = %d\n", socktype);
        printf("passive = %d\n",  passive);*/

	if (sockaddrfill(&sa,hostname,service,family,socktype,passive)<0) {
		return -1;
	}
	if (ip!=(void *)0) {
		//*ip = ntohl(sa.sin_addr.s_addr);
                memcpy(ip, &sa.sin6_addr.s6_addr, sizeof *ip);
                //*ip = sa.sin6_addr.s6_addr
	}
	if (port!=(void *)0) {
		*port = ntohs(sa.sin_port);
	}
        lzfs_pretty_syslog(LOG_WARNING,"hostname = %s", hostname);
        lzfs_pretty_syslog(LOG_WARNING,"service = %s", service);
        struct in_addr ip_addr;
        ip_addr.s_addr = *ip;
        lzfs_pretty_syslog(LOG_WARNING,"ip = %s", inet_ntoa(ip_addr));
        lzfs_pretty_syslog(LOG_WARNING,"port = %" PRIu16 "", *port); //warning: format ‘%u’ expects argument of type ‘unsigned int’, but argument 3 has type ‘uint16_t* {aka short unsigned int*}’ [-Wf$
        lzfs_pretty_syslog(LOG_WARNING,"family = %d", family);
        lzfs_pretty_syslog(LOG_WARNING,"socktype = %d", socktype);
        lzfs_pretty_syslog(LOG_WARNING,"passive = %d", passive);

	return 0;
}

static inline int socknonblock(int sock) {
#ifdef O_NONBLOCK
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) {
		return -1;
	}
	return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#else
	int yes = 1;
	return ioctl(sock, FIONBIO, &yes);
#endif
}

/* ----------------- TCP ----------------- */

int tcpsetacceptfilter(int sock) {
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg afa;

	bzero(&afa, sizeof(afa));
	strcpy(afa.af_name, "dataready");
	return setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa));
#elif TCP_DEFER_ACCEPT
	int v = 1;

	return setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT, &v, sizeof(v));
#else
	(void)sock;
	errno=ENOTSUP;
	return -1;
#endif
}

int tcpsocket(void) {
        int sock = socket(AF_INET6,SOCK_STREAM,0);
        int opt = 0;
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
                throw InitializeException("tcplibrary: can't init socket :" + errorString(errno));
        }
	return sock;
}

int tcpnonblock(int sock) {
	return socknonblock(sock);
}

int tcpresolve(const char *hostname,const char *service,uint32_t *ip,uint16_t *port,int passive) {
	return sockresolve(hostname,service,ip,port,AF_UNSPEC,SOCK_STREAM,passive);
}

int tcpreuseaddr(int sock) {
	int yes=1;
	return setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(int));
}

int tcpnodelay(int sock) {
	int yes=1;
	return setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,(char*)&yes,sizeof(int));
}

int tcpaccfhttp(int sock) {
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg afa;

	bzero(&afa, sizeof(afa));
	strcpy(afa.af_name, "httpready");
	return setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa));
#else
	(void)sock;
	errno=EINVAL;
	return -1;
#endif
}

int tcpaccfdata(int sock) {
#ifdef SO_ACCEPTFILTER
	struct accept_filter_arg afa;

	bzero(&afa, sizeof(afa));
	strcpy(afa.af_name, "dataready");
	return setsockopt(sock, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa));
#else
	(void)sock;
	errno=EINVAL;
	return -1;
#endif
}

int tcpstrbind(int sock,const char *hostname,const char *service) {
	struct sockaddr_in sa;
	if (sockaddrfill(&sa,hostname,service,AF_UNSPEC,SOCK_STREAM,1)<0) {
		return -1;
	}
	if (bind(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) < 0) {
		return -1;
	}
	return 0;
}

int tcpnumbind(int sock,uint32_t ip,uint16_t port) {
	struct sockaddr_in sa;
	sockaddrnumfill(&sa,ip,port);
	if (bind(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) < 0) {
		return -1;
	}
	return 0;
}

int tcpstrconnect(int sock,const char *hostname,const char *service) {
	struct sockaddr_in sa;
	if (sockaddrfill(&sa,hostname,service,AF_UNSPEC,SOCK_STREAM,0)<0) {
		return -1;
	}
	if (connect(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) >= 0) {
		return 0;
	}
	if (errno == EINPROGRESS) {
		return 1;
	}
	return -1;
}

int tcpnumconnect(int sock,uint32_t ip,uint16_t port) {
	struct sockaddr_in sa;
	sockaddrnumfill(&sa,ip,port);
	if (connect(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) >= 0) {
		return 0;
	}
	if (errno == EINPROGRESS) {
		return 1;
	}
	return -1;
}

int tcpstrtoconnect(int sock,const char *hostname,const char *service,uint32_t msecto) {
	struct sockaddr_in sa;
	if (socknonblock(sock)<0) {
		return -1;
	}
	if (sockaddrfill(&sa,hostname,service,AF_UNSPEC,SOCK_STREAM,0)<0) {
		return -1;
	}
	if (connect(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) >= 0) {
		return 0;
	}
	if (errno == EINPROGRESS) {
		struct pollfd pfd;
		pfd.fd = sock;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		if (poll(&pfd,1,msecto)<0) {
			return -1;
		}
		if (pfd.revents & POLLOUT) {
			return tcpgetstatus(sock);
		}
		errno=ETIMEDOUT;
	}
	return -1;
}

int tcpnumtoconnect(int sock,uint32_t ip,uint16_t port,uint32_t msecto) {
	struct sockaddr_in sa;
	if (socknonblock(sock)<0) {
		return -1;
	}
	sockaddrnumfill(&sa,ip,port);
	if (connect(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) >= 0) {
		return 0;
	}
	if (errno == EINPROGRESS) {
		struct pollfd pfd;
		pfd.fd = sock;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		if (poll(&pfd,1,msecto)<0) {
			return -1;
		}
		if (pfd.revents & POLLOUT) {
			return tcpgetstatus(sock);
		}
		errno=ETIMEDOUT;
	}
	return -1;
}

int tcpgetstatus(int sock) {
	socklen_t arglen = sizeof(int);
	int rc = 0;
	if (getsockopt(sock,SOL_SOCKET,SO_ERROR,(void *)&rc,&arglen) < 0) {
		rc=errno;
	}
	errno=rc;
	return rc;
}

int tcpstrlisten(int sock,const char *hostname,const char *service,uint16_t queue) {
	struct sockaddr_in sa;

        //#anchor

	if (sockaddrfill(&sa,hostname,service,AF_UNSPEC,SOCK_STREAM,1)<0) {
		return -1;
	}
	if (bind(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) < 0) {
		return -1;
	}
	if (listen(sock,queue)<0) {
		return -1;
	}
	return 0;
}

int tcpnumlisten(int sock,uint32_t ip,uint16_t port,uint16_t queue) {
	struct sockaddr_in sa;
	sockaddrnumfill(&sa,ip,port);
	if (bind(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in)) < 0) {
                lzfs_pretty_syslog(LOG_ERR,"tcpnumlisten has been failed at bind stage!");
		return -1;
	}
	if (listen(sock,queue)<0) {
                lzfs_pretty_syslog(LOG_ERR,"tcpnumlisten has been failed at listen stage!");
		return -1;
	}
	return 0;
}

int tcpaccept(int lsock) {
	int sock;
	sock=accept(lsock,(struct sockaddr *)NULL,0);
	if (sock<0) {
		return -1;
	}
	return sock;
}

int tcpgetpeer(int sock,uint32_t *ip,uint16_t *port) {
	struct sockaddr_in sa;
	socklen_t leng;
	leng=sizeof(sa);
	if (getpeername(sock,(struct sockaddr *)&sa,&leng)<0) {
		return -1;
	}
	if (ip!=(void *)0) {
		*ip = ntohl(sa.sin_addr.s_addr);
	}
	if (port!=(void *)0) {
		*port = ntohs(sa.sin_port);
	}
	return 0;
}

int tcpgetmyaddr(int sock,uint32_t *ip,uint16_t *port) {
	struct sockaddr_in sa;
	socklen_t leng;
	leng=sizeof(sa);
	if (getsockname(sock,(struct sockaddr *)&sa,&leng)<0) {
		return -1;
	}
	if (ip!=(void *)0) {
		*ip = ntohl(sa.sin_addr.s_addr);
	}
	if (port!=(void *)0) {
		*port = ntohs(sa.sin_port);
	}
	return 0;
}

int tcpclose(int sock) {
	// make sure that all pending data in the output buffer will be sent
	shutdown(sock,SHUT_WR);
	return close(sock);
}

int tcptopoll(int sock,int events,uint32_t msecto) {
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = events;
	pfd.revents = 0;
	return poll(&pfd,1,msecto);
}

int32_t tcptoread(int sock,void *buff,uint32_t leng,uint32_t msecto) {
	uint32_t rcvd=0;
	int i;
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLIN;
	while (rcvd<leng) {
		pfd.revents = 0;
		if (poll(&pfd,1,msecto)<0) {
			return -1;
		}
		if (pfd.revents & POLLIN) {
			i = read(sock,((uint8_t*)buff)+rcvd,leng-rcvd);
			if (i == 0 || (i < 0 && errno != EAGAIN)) {
				return i;
			} else if (i > 0) {
				rcvd+=i;
			}
		} else {
			errno = ETIMEDOUT;
			return -1;
		}
	}
	return rcvd;
}

int32_t tcptowrite(int sock,const void *buff,uint32_t leng,uint32_t msecto) {
	uint32_t sent=0;
	int i;
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLOUT;
	while (sent<leng) {
		pfd.revents = 0;
		if (poll(&pfd,1,msecto)<0) {
			return -1;
		}
		if (pfd.revents & POLLOUT) {
			i = write(sock,((uint8_t*)buff)+sent,leng-sent);
			if (i == 0 || (i < 0 && errno != EAGAIN)) {
				return i;
			} else if (i > 0) {
				sent+=i;
			}
		} else {
			errno = ETIMEDOUT;
			return -1;
		}
	}
	return sent;
}

int tcptoaccept(int sock,uint32_t msecto) {
	struct pollfd pfd;
	pfd.fd = sock;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd,1,msecto)<0) {
		return -1;
	}
	if (pfd.revents & POLLIN) {
		return accept(sock,(struct sockaddr *)NULL,0);
	}
	errno = ETIMEDOUT;
	return -1;
}

/* ----------------- UDP ----------------- */

int udpsocket(void) {
	return socket(AF_UNSPEC,SOCK_DGRAM,0);
}

int udpnonblock(int sock) {
	return socknonblock(sock);
}

int udpresolve(const char *hostname,const char *service,uint32_t *ip,uint16_t *port,int passive) {
	return sockresolve(hostname,service,ip,port,AF_UNSPEC,SOCK_DGRAM,passive);
}

int udpnumlisten(int sock,uint32_t ip,uint16_t port) {
	struct sockaddr_in sa;
	sockaddrnumfill(&sa,ip,port);
	return bind(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in));
}

int udpstrlisten(int sock,const char *hostname,const char *service) {
	struct sockaddr_in sa;
	if (sockaddrfill(&sa,hostname,service,AF_UNSPEC,SOCK_DGRAM,1)<0) {
		return -1;
	}
	return bind(sock,(struct sockaddr *)&sa,sizeof(struct sockaddr_in));
}

int udpwrite(int sock,uint32_t ip,uint16_t port,const void *buff,uint16_t leng) {
	struct sockaddr_in sa;
	if (leng>512) {
		return -1;
	}
	sockaddrnumfill(&sa,ip,port);
	return sendto(sock,buff,leng,0,(struct sockaddr *)&sa,sizeof(struct sockaddr_in));
}

int udpread(int sock,uint32_t *ip,uint16_t *port,void *buff,uint16_t leng) {
	socklen_t templeng;
	struct sockaddr tempaddr;
	struct sockaddr_in *saptr;
	int ret;
	ret = recvfrom(sock,buff,leng,0,&tempaddr,&templeng);
	if (templeng==sizeof(struct sockaddr_in)) {
		saptr = ((struct sockaddr_in*)&tempaddr);
		if (ip!=(void *)0) {
			*ip = ntohl(saptr->sin_addr.s_addr);
		}
		if (port!=(void *)0) {
			*port = ntohs(saptr->sin_port);
		}
	}
	return ret;
}

int udpclose(int sock) {
	return close(sock);
}
