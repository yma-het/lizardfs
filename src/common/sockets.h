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

#pragma once

#include "common/platform.h"

#include <inttypes.h>
#include <sys/poll.h>

/* ----------------- TCP ----------------- */

int tcpsocket(void);
int tcpresolve(const char *hostname,const char *service,struct in6_addr *ip,uint16_t *port,int passiveflag);
int tcpnonblock(int sock);
int tcpsetacceptfilter(int sock);
int tcpreuseaddr(int sock);
int tcpnodelay(int sock);
int tcpaccfhttp(int sock);
int tcpaccfdata(int sock);
int tcpnumbind(int sock,struct in6_addr *ip,uint16_t port);
int tcpstrbind(int sock,const char *hostname,const char *service);
int tcpnumconnect(int sock,struct in6_addr *ip,uint16_t port);
int tcpnumtoconnect(int sock,struct in6_addr *ip,uint16_t port,uint32_t msecto);
int tcpstrconnect(int sock,const char *hostname,const char *service);
int tcpstrtoconnect(int sock,const char *hostname,const char *service,uint32_t msecto);
int tcpgetstatus(int sock);
int tcpnumlisten(int sock,struct in6_addr *ip,uint16_t port,uint16_t queue);
int tcpstrlisten(int sock,const char *hostname,const char *service,uint16_t queue);
int tcpaccept(int lsock);
int tcpgetpeer(int sock,struct in6_addr *ip,uint16_t *port);
int tcpgetmyaddr(int sock,struct in6_addr *ip,uint16_t *port);
int tcpclose(int sock);
int tcptopoll(int sock,int events,uint32_t msecto);
int32_t tcptoread(int sock,void *buff,uint32_t leng,uint32_t msecto);
int32_t tcptowrite(int sock,const void *buff,uint32_t leng,uint32_t msecto);
int tcptoaccept(int sock,uint32_t msecto);

/* ----------------- UDP ----------------- */

int udpsocket(void);
int udpresolve(const char *hostname,const char *service,struct in6_addr *ip,uint16_t *port,int passiveflag);
int udpnonblock(int sock);
int udpnumlisten(int sock,struct in6_addr *ip,uint16_t port);
int udpstrlisten(int sock,const char *hostname,const char *service);
int udpwrite(int sock,struct in6_addr *ip,uint16_t port,const void *buff,uint16_t leng);
int udpread(int sock,struct in6_addr *ip,uint16_t *port,void *buff,uint16_t leng);
int udpclose(int sock);
