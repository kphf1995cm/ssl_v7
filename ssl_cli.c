/*
 * File: ssl_cli.c
 * ---------------
 * Description: This program socket client by using SSL. 
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utility.h"
#include "packaging.h"


void ShowCerts(SSL * ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		printf("(Digital Certificate Mesage:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Certificate: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	} else
		printf("No Digital Certificate!\n");
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		printf("Usage: %s IP Port\n", argv[0]);
		return EXIT_FAILURE;
	}

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx;
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		return EXIT_FAILURE;
	}

	int sockfd;
	if ((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		ERR_EXIT("socket");

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(atoi(argv[2]));
	servaddr.sin_addr.s_addr = inet_addr(argv[1]);

	if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
		ERR_EXIT("connect");

	SSL *ssl;
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	if (SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else {
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}

	struct packet sendbuf;
	struct packet recvbuf;
	memset(&sendbuf, 0, sizeof(sendbuf));
	memset(&recvbuf, 0, sizeof(recvbuf));
	int n;
	while (fgets(sendbuf.buf, sizeof(sendbuf.buf), stdin) != NULL) { 
		n = strlen(sendbuf.buf)-1; /* cut off the '\n' */
		sendbuf.len = htonl(n);
		SSL_writen(ssl, &sendbuf, 4+n); /* header+payload */

		int ret = SSL_readn(ssl, &recvbuf.len, 4); /* recv 4 bytes first */
		if (ret == -1)
				ERR_EXIT("SSL_readn");
		else if (ret < 4) {
			printf("client close\n");	
			break;
		}
		n = ntohl(recvbuf.len);
		ret = SSL_readn(ssl, recvbuf.buf, n);
		if (ret == -1)
			ERR_EXIT("SSL_readn");
		else if (ret < n) {
			printf("client close\n");	
			break;
		}

		fputs(recvbuf.buf, stdout);
		memset(&sendbuf, 0, sizeof(sendbuf));
		memset(&recvbuf, 0, sizeof(recvbuf));
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}
