/*
 * File: packaging.h
 * -----------------
 * Description: Define the packet struct.
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#ifndef PACKAGING_H
#define PACKAGING_H

struct packet {
	int len;		/* header */
    char buf[1024];	/* payload */
};

ssize_t readn(int fd, void *buf, size_t count);
ssize_t writen(int fd, const void *buf, size_t count);
int SSL_readn(SSL *ssl, void *buf, int count);
int SSL_writen(SSL *ssl, const void *buf, int count);

#endif
