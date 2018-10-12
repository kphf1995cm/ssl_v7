/*
 * File: ssl_srv.c
 * ---------------
 * Description: This program socket server by using SSL. 
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "utility.h"
#include "packaging.h"
#include "mysql_interface.h"
#include "Sha256Calc.h"
#include "dlist.h"

#define CENTER_SRVIP	"211.68.122.70"

const char CCH[] = "0123456789abcdef";

DList nid_local;
DList nid_nonlocal;


void usage()
{
	printf("Usage: ./ssl_srv -p port -r rsa_key -c cert\n");
}

int forward_recv2center(char *query_or_auth, char *result)
{
	int sock;
	if ( (sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		ERR_EXIT("socket");

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(5188);
    servaddr.sin_addr.s_addr = inet_addr(CENTER_SRVIP);

    if (connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
       	ERR_EXIT("connect");

	struct packet sendbuf;
	struct packet recvbuf;
    memset(&sendbuf, 0, sizeof(sendbuf));
    memset(&recvbuf, 0, sizeof(recvbuf));
	strcpy(sendbuf.buf, query_or_auth);
    int n = strlen(sendbuf.buf);
	sendbuf.len = htonl(n);
	printf("[forward_recv2center]: sendbuf.buf = %s\n", sendbuf.buf);
    writen(sock, &sendbuf, 4+n); 
    int ret = readn(sock, &recvbuf.len, 4); 
    if (ret == -1)
     	ERR_EXIT("readn");
    else if (ret < 4) { 
    	printf("server close\n");
		return -1;
	}
	n = ntohl(recvbuf.len);
	ret = readn(sock, recvbuf.buf, n);
	if (ret == -1)
    	ERR_EXIT("readn");
    else if (ret < n) {
		printf("server close\n");
		return -1;
	}
	printf("[forward_recv2center]: recvbuf.buf = %s\n", recvbuf.buf);

	strcpy(result, recvbuf.buf);
	close(sock);
	return 0;
}

void do_service(SSL *ssl, char *cliip)
{
	struct packet recvbuf;
	while (1) {
		memset(&recvbuf, 0, sizeof(recvbuf));
		int ret = SSL_readn(ssl, &recvbuf.len, 4); /* recv the header */
		if (ret == -1) 
			ERR_EXIT("SSL_readn");
		else if (ret < 4) {
			printf("client close\n");
			break;
		}
		int n = ntohl(recvbuf.len);
		ret = SSL_readn(ssl, recvbuf.buf, n);
		if (ret == -1) 
			ERR_EXIT("SSL_readn");
		else if (ret < n) {
			printf("client close\n");
			break;
		}
		printf("[do_service]: Recv [%s] from [%s], len = %d\n", recvbuf.buf, cliip, n);

		/* Get content we need */
		char nid[16] = {0};
		char digest[64] = {0};
		char ip[64] = {0};
		char mytime[32] = {0};
		char mac[13] = {0};
		char hmac[5] = {0}; /* 18-bit */
		char idea_key[33] = {0}; /* 32+1 */
		char send_cont[1024] = {0};
		char nonlocal_result[1024] = {0};
		int send_contlen = 0;
		char *ptr, *saveptr;
		
		DListElmt *travel;

		/*
		 * Query	
		 * -----
		 * 	nid:xxx	<-> nid:xxx;ans:yes;nonce:xxx
		 * 			<-> nid:xxx;ans:no
		 * Auth
		 * ----
		 * 	nid:xxx;digest:xxx;mac:xxx	<->	nid:xxx;auth:yes;hmac:xxx;idea_mac:xxx
		 * 								<->	nid:xxx;auth:yes;idea_time:xxx
		 * 								<-> nid:xxx;auth:no
		 * Msg
		 * ---
		 * 	nid:xxx;ip:xxx;time:xxx;mac:xxx
		 */
		if (strstr(recvbuf.buf, "nid:") && !strchr(recvbuf.buf, ';') ) {
			strcpy(nid, strchr(recvbuf.buf, ':')+1);
			printf("[do_service|Query]: nid: %s\n", nid);
			if (query_nid(nid)) { /* local found */
				srand((unsigned)time(NULL));
				int nonce = rand();
				sprintf(send_cont, "nid:%s;ans:yes;nonce:%d", nid, nonce); 
				update_nonce(nid, nonce);
				for (travel = dlist_head(&nid_local); travel != NULL; travel = dlist_next(travel))
					if (strcmp((const char *)dlist_data(travel), nid) == 0) 
						break;
				if (travel == NULL)
					dlist_ins_next(&nid_local, nid_local.head, nid);
			} else {
				memset(nonlocal_result, 0, 1024);
				forward_recv2center(recvbuf.buf, nonlocal_result);
				strcpy(send_cont, nonlocal_result);
				for (travel = dlist_head(&nid_nonlocal); travel != NULL; travel = dlist_next(travel))
					if (strcmp((const char *)dlist_data(travel), nid) == 0) 
						break;
				if (travel == NULL)
					dlist_ins_next(&nid_nonlocal, nid_nonlocal.head, nid);
			}
			printf("[QUERY] nid_local:%p, nid_local.size = %d\n", &nid_local, dlist_size(&nid_local));
			printf("[QUERY] nid_nonlocal:%p, nid_nonlocal.size = %d\n", &nid_nonlocal, dlist_size(&nid_nonlocal));

		} else if (strstr(recvbuf.buf, "nid:") && strstr(recvbuf.buf, "digest:") && strstr(recvbuf.buf, "mac:") ) {
			char backup_for_send[1024] = {0};
			strcpy(backup_for_send, recvbuf.buf);
			char tmp[3][128] = {{0}, {0}, {0}};
			ptr = strtok_r(recvbuf.buf, ";", &saveptr);
			int i;
			for (i = 0; i < 3; ++i) {
				strcpy(tmp[i], ptr);
				ptr = strtok_r(NULL, ";", &saveptr);	
			}
			strtok_r(tmp[0], ":", &saveptr);
        	strcpy(nid, saveptr); 
			strtok_r(tmp[1], ":", &saveptr);
        	strcpy(digest, saveptr); 
			strtok_r(tmp[2], ":", &saveptr);
        	strcpy(mac, saveptr); 
			printf("[do_service|Auth]: nid = %s, digest = %s, mac = %s\n", nid, digest, mac);

			int auth_pass_local = 0;
			int auth_pass_nonlocal = 0;

			/* Whether the local nid query */
			for (travel = dlist_head(&nid_local); travel != NULL; travel = dlist_next(travel)) {
				printf("local travel: %s\n", dlist_data(travel));
				if (strcmp((const char *)dlist_data(travel), nid) == 0) 
					if (auth_passwdnonce(nid, digest)) /* local pass */
						auth_pass_local = 1;
			}

			/* Whether the nonlocal nid query */
			for (travel = dlist_head(&nid_nonlocal); travel != NULL; travel = dlist_next(travel)) {
				printf("nonlocal travel: %s\n", dlist_data(travel));
				if (strcmp((const char *)dlist_data(travel), nid) == 0) {
					memset(nonlocal_result, 0, 1024);
					forward_recv2center(backup_for_send, nonlocal_result);
					strcpy(send_cont, nonlocal_result);
					if (strstr(send_cont, ":yes")) /* nonlocal pass */
						auth_pass_nonlocal = 1;
				} 
			}

			if (auth_pass_local || auth_pass_nonlocal) {
				if (idea_mac(idea_key) && strlen(mac)) { /* idea_mac */
                    srand((unsigned)time(NULL));
                    int i;
                    for (i = 0; i < 4; ++i) {
                        int x = rand() / (RAND_MAX / (sizeof(CCH) - 1));
                        hmac[i] = CCH[x];
                    }
                    sprintf(send_cont, "nid:%s;auth:yes;hmac:%s;idea_mac:%s", nid, hmac, idea_key);
                    insert_NA_MACHASH(nid, mac, hmac);
                } else /* idea_time */
                    sprintf(send_cont, "nid:%s;auth:yes;idea_time:%s", nid, idea_key);
                printf("[do_service|Auth]: idea_key = %s\n", idea_key);
			} else 
            	sprintf(send_cont, "nid:%s;auth:no", nid);

		} else if (strstr(recvbuf.buf, "nid:") && strstr(recvbuf.buf, "ip:") && strstr(recvbuf.buf, "time:") && strstr(recvbuf.buf, "mac:")) {
			char tmp[4][128] = {{0}, {0}, {0}, {0}};
			char *data;
			ptr = strtok_r(recvbuf.buf, ";", &saveptr);
			int i;
			for (i = 0; i < 4; ++i) {
				strcpy(tmp[i], ptr);
				ptr = strtok_r(NULL, ";", &saveptr);	
			}
			strtok_r(tmp[0], ":", &saveptr);
        	strcpy(nid, saveptr); 
        	strcpy(ip, tmp[1]+3); /* skip ip: */
        	strcpy(mytime, tmp[2]+5); /* skip time: */
			strtok_r(tmp[3], ":", &saveptr);
        	strcpy(mac, saveptr); 
			printf("nid: %s\n", nid);
			printf("ip: %s\n", ip);
			printf("time: %s\n", mytime);
			printf("mac: %s\n", mac);

			for (travel = dlist_head(&nid_local); travel != NULL; travel = dlist_next(travel))
				if (strcmp((const char *)dlist_data(travel), nid) == 0) {
					insert_radpostauth(nid, ip, mytime, mac);
					dlist_remove(&nid_local, travel, (void **)&data);	
				}
			
			for (travel = dlist_head(&nid_nonlocal); travel != NULL; travel = dlist_next(travel)) 
				if (strcmp((const char *)dlist_data(travel), nid) == 0) {
					insert_radpostauth(nid, ip, mytime, mac);
					dlist_remove(&nid_nonlocal, travel, (void **)&data);	
				}

			printf("[INSERT] nid_local:%p, nid_local.size = %d\n", &nid_local, dlist_size(&nid_local));
			printf("[INSERT] nid_nonlocal:%p, nid_nonlocal.size = %d\n", &nid_nonlocal, dlist_size(&nid_nonlocal));

		} else 
			sprintf(send_cont, "Unknown msg type\n");

		/* Send to cli */
		struct packet sendbuf;
		memset(&sendbuf, 0, sizeof(sendbuf));
		send_contlen = strlen(send_cont);
		sendbuf.len = htonl(send_contlen);
		strcpy(sendbuf.buf, send_cont);
		SSL_writen(ssl, &sendbuf, 4+send_contlen);
	}
}


void handle_sigchld(int sig)
{
	while (waitpid(-1, NULL, WNOHANG) > 0); /* 用循环保证所有的僵尸进程都被处理 */
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		usage();
		return EXIT_FAILURE;
	}

	int opt;
	uint16_t myport;
	char *rsa_key, *cert;
	while ((opt = getopt(argc, argv, "p:r:c:")) != -1) {
		switch (opt) {
		case 'p':
			if (optarg == NULL || *optarg == '-') {
				fprintf(stderr, "Please set the port.\n");
				return EXIT_FAILURE;
			}
			myport = atoi(optarg);
			break;
		case 'r':
			if (optarg == NULL || *optarg == '-') {
				fprintf(stderr,
					"Please set the RSA secret key.\n");
				return EXIT_FAILURE;
			}
			rsa_key = optarg;
			break;
		case 'c':
			if (optarg == NULL || *optarg == '-') {
				fprintf(stderr,
					"Please set the certificate.\n");
				return EXIT_FAILURE;
			}
			cert = optarg;
			break;
		default:
			printf("Other options: %c\n", opt);
			usage();
		}
	}

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	SSL_CTX *ctx;
	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, rsa_key, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	signal(SIGCHLD, handle_sigchld);

	int listenfd;
	if ((listenfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		ERR_EXIT("socket");

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(myport);
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	int on = 1;
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		ERR_EXIT("setsockopt");

	if (bind
	    (listenfd, (struct sockaddr *)&servaddr,
	     sizeof(struct sockaddr)) < 0)
		ERR_EXIT("bind");

	if (listen(listenfd, SOMAXCONN) < 0)
		ERR_EXIT("listen");

	struct sockaddr_in peeraddr;
	socklen_t peerlen = sizeof(peeraddr);

	int conn;
	pid_t pid;
	SSL *ssl;
	dlist_init(&nid_local, free);
	dlist_init(&nid_nonlocal, free);
	while (1) {
		if ((conn = accept(listenfd, (struct sockaddr *)&peeraddr, &peerlen)) < 0)
			ERR_EXIT("accept");
		struct timeval start, end;
		gettimeofday(&start, NULL);
		printf("Got connect: ip = %s, port = %d\n",
		       inet_ntoa(peeraddr.sin_addr), ntohs(peeraddr.sin_port));

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, conn);
		if (SSL_accept(ssl) < 0)
			ERR_EXIT("SSL_accept");

		pid = fork();
		if (pid == -1)
			ERR_EXIT("fork");
		if (pid == 0) {
			close(listenfd);
			gettimeofday(&start, NULL);
			printf("connect spend: %f sec\n", (1000000*(end.tv_sec-start.tv_sec) + end.tv_usec-start.tv_usec)/1000000);
			do_service(ssl, inet_ntoa(peeraddr.sin_addr));
			exit(EXIT_SUCCESS);
		} else
			close(conn);
	}
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}
