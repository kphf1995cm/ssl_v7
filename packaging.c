/*
 * File: packaging.c
 * -----------------
 * Description: This program is a wrapper of read/write. 
 * 	And we packing a packet struct to deal with TCP splicing.
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "packaging.h"


/* Packaging readn() */
ssize_t readn(int fd, void *buf, size_t count)
{   
    size_t nleft = count;   
    ssize_t nread;      
    char *bufp = (char *)buf;
    while (nleft > 0) {
        if ((nread = read(fd, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nread == 0) 
            return count - nleft;
        bufp += nread;
        nleft -= nread;
    }
    return count;
}

/* Packaging writen() */
ssize_t writen(int fd, const void *buf, size_t count)
{   
    size_t nleft = count;  
    ssize_t nwriten;   
    char *bufp = (char *)buf;
    while (nleft > 0) {
        if ((nwriten = write(fd, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nwriten == 0) 
            continue;
        bufp += nwriten;
        nleft -= nwriten;
    }
    return count;
}

/* Packaging SSL_read() */
int SSL_readn(SSL *ssl, void *buf, int count)
{
    int nleft = count;   
    int nread;     
    char *bufp = (char *)buf;
    while (nleft > 0) {
        if ((nread = SSL_read(ssl, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nread == 0)  /* peer have closed */
            return count - nleft;
        bufp += nread;
        nleft -= nread;
    }
    return count;
}

/* Packaging SSL_write() */
int SSL_writen(SSL *ssl, const void *buf, int count)
{
    int nleft = count;  
    int nwriten; 
    char *bufp = (char *)buf;
    while (nleft > 0) {
        if ((nwriten = SSL_write(ssl, bufp, nleft)) < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        } else if (nwriten == 0)	/* waiting for peer close */
            continue;
        bufp += nwriten;
        nleft -= nwriten;
    }
    return count;
}
