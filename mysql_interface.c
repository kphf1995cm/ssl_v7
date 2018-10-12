/*
 * File: mysql_interface.c
 * -----------------------
 * Description: This program is the MySQL interface.
 * 	@query_nid:			Query nid whether in the db.
 *	@update_nonce:		Upgrade the nonce, and then insert to the db.
 *	@auth_passwdnonce: 	Auth, MD5(passwd+nonce) == digest? 
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include "mysql_interface.h"

int query_nid(char *nid)
{
	MYSQL *conn_teledata;
	MYSQL_RES *res_teledata;
	MYSQL_ROW row_teledata;

	conn_teledata = mysql_init(NULL);
	if (!conn_teledata) {
		fprintf(stderr, "mysql_init failed\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect
	    (conn_teledata, DATABASE_IP, "root", "YUIOPPOIUY",
	     "cngi", 3306, NULL, 0)) {
		int teledata = mysql_query(conn_teledata, "SELECT LOGIN_NAME FROM C_USER");
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) {
				while ((row_teledata = mysql_fetch_row(res_teledata))) 
						if (strcmp(*row_teledata, nid) == 0) 
							return 1;
				mysql_free_result(res_teledata);
			}
		} else
			printf("SELECT error: %s\n", mysql_error(conn_teledata));
	} else {
		fprintf(stderr, "Connection failed\n");
		if (mysql_errno(conn_teledata))
			fprintf(stderr, "Connection error %d: %s\n",
				mysql_errno(conn_teledata),
				mysql_error(conn_teledata));
	}
	mysql_close(conn_teledata);
	return 0;
}				

int update_nonce(char *nid, int nonce)
{
	MYSQL *conn_teledata;
	MYSQL_RES *res_teledata;
	MYSQL_ROW row_teledata;

	char sql_cmd[1024] = {0};

	conn_teledata = mysql_init(NULL);
	if (!conn_teledata) {
		fprintf(stderr, "mysql_init failed\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect
	    (conn_teledata, DATABASE_IP, "root", "YUIOPPOIUY",
	     "cngi", 3306, NULL, 0)) {
		snprintf(sql_cmd, 1024, "update C_USER set NONECE=%d where LOGIN_NAME='%s'", nonce, nid);
		int teledata = mysql_query(conn_teledata, sql_cmd);
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) {
				while ((row_teledata = mysql_fetch_row(res_teledata))) 
					if (strcmp(*row_teledata, nid) == 0) 
						return 1;
				mysql_free_result(res_teledata);
			}
		} else
			printf("UPDATA error: %s\n", mysql_error(conn_teledata));
	} else {
		fprintf(stderr, "Connection failed\n");
		if (mysql_errno(conn_teledata))
			fprintf(stderr, "Connection error %d: %s\n",
				mysql_errno(conn_teledata),
				mysql_error(conn_teledata));
	}
	mysql_close(conn_teledata);
	return 0;
}				

int auth_passwdnonce(char *nid, char *digest)
{
	MYSQL *conn_teledata;
	MYSQL_RES *res_teledata;
	MYSQL_ROW row_teledata;

	char sql_cmd[1024] = {0};
	char nonce[32] = {0};
	char passwd[64] = {0};
	char passwd_nonce[128] = {0};
	char md5_passwd_nonce[256] = {0};

	conn_teledata = mysql_init(NULL);
	if (!conn_teledata) {
		fprintf(stderr, "mysql_init failed\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect
	    (conn_teledata, DATABASE_IP, "root", "YUIOPPOIUY",
	     "cngi", 3306, NULL, 0)) {
		snprintf(sql_cmd, 1024, "select PASSWD, NONECE from C_USER where LOGIN_NAME='%s'", nid);
		int teledata = mysql_query(conn_teledata, sql_cmd);
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) {
				while ((row_teledata = mysql_fetch_row(res_teledata))) {
					strncpy(passwd, row_teledata[0], strlen(row_teledata[0]));
					strncpy(nonce, row_teledata[1], strlen(row_teledata[1]));
				}
				mysql_free_result(res_teledata);
			}
		} else
			printf("SELECT error: %s\n", mysql_error(conn_teledata));
	} else {
		if (mysql_errno(conn_teledata))
			fprintf(stderr, "Connection error %d: %s\n",
				mysql_errno(conn_teledata),
				mysql_error(conn_teledata));
	}
	mysql_close(conn_teledata);
	
	printf("passwd = %s\n", passwd);
	printf("nonce = %s\n", nonce);
	strcpy(passwd_nonce, passwd);
	strcat(passwd_nonce, nonce);
	printf("passwd_nonce = %s\n", passwd_nonce);

	/* MD5 sum */
	unsigned char md[MD5_DIGEST_LENGTH];
	MD5((const unsigned char *)passwd_nonce, strlen(passwd_nonce), md);
	printf("MD5: ");
	int i;
	char tmp[4] = {0};
	for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
		printf("%02x", md[i]);
		snprintf(tmp, 3, "%02x", md[i]);
		strcat(md5_passwd_nonce, tmp);
	}
	printf("\tmd5_passwd_nonce: %s\n", md5_passwd_nonce);

	if (strncmp(digest, md5_passwd_nonce, strlen(md5_passwd_nonce)) == 0)
		return 1;

	return 0;
}

/*
 * return 0: intra
 * return 1: external
 */
int intra_or_external(char *nid)
{
	MYSQL *conn_teledata;
	MYSQL_RES *res_teledata;
	MYSQL_ROW row_teledata;

	char group_id[4] = {0};
	char divid_id[8] = {0};
	char org_id[32] = {0};
	char sql_cmd[1024] = {0};

	conn_teledata = mysql_init(NULL);
	if (!conn_teledata) {
		fprintf(stderr, "mysql_init failed\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect
	    (conn_teledata, DATABASE_IP, "root", "YUIOPPOIUY",
	     "cngi", 3306, NULL, 0)) {
		snprintf(sql_cmd, 1024, "select GROUP_ID from C_USER where LOGIN_NAME='%s'", nid);
		int teledata = mysql_query(conn_teledata, sql_cmd);
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) {
				while ((row_teledata = mysql_fetch_row(res_teledata))) 
					strncpy(group_id, *row_teledata, strlen(*row_teledata));
				mysql_free_result(res_teledata);
			}
		} else
			printf("SELECT error: %s\n", mysql_error(conn_teledata));

		printf("group_id = %s\n", group_id);

		memset(sql_cmd, 0, sizeof(sql_cmd));
		snprintf(sql_cmd, 1024, "select divid_id, org_id from C_GROUP where ID ='%s'", group_id);
		teledata = mysql_query(conn_teledata, sql_cmd);
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) {
				while ((row_teledata = mysql_fetch_row(res_teledata))) {
					strncpy(divid_id, row_teledata[0], strlen(row_teledata[0]));
					strncpy(org_id, row_teledata[1], strlen(row_teledata[1]));
				}
				mysql_free_result(res_teledata);
			}
		} else
			printf("SELECT error: %s\n",
			       mysql_error(conn_teledata));
	} else {
		fprintf(stderr, "Connection failed\n");
		if (mysql_errno(conn_teledata))
			fprintf(stderr, "Connection error %d: %s\n",
				mysql_errno(conn_teledata),
				mysql_error(conn_teledata));
	}
	mysql_close(conn_teledata);
	
	char *index[16] = {
		"0000",
    	"0001",
    	"0010",
    	"0011",
    	"0100",
    	"0101",
    	"0110",
    	"0111",
    	"1000",
    	"1001",
    	"1010",
    	"1011",
    	"1100",
    	"1101",
    	"1110",
    	"1111"
	};
	/*
	 * nid[0] == divid_id
	 * nid[1]nid[2]nid[3]nid[4]nid[5] > org_id
	 */
	char org_in_nid[21] = {0}; /* 4*5+1('\0') */
	int value = 0;
	value = nid[0] - '0';
	if (value > 9) /* a-f */
		value -= 39;
	printf("divid_id: \t%s\n", divid_id);
	printf("nid[0]: \t%s\n", index[value]);
	if (strcmp(index[value], divid_id) == 0) { /* divid_id is same */
		int i;
		for (i = 1; i < 6; ++i) {
			value = nid[i] - '0';
			if (value > 9) /* a-f */
				value -= 39;
			strcat(org_in_nid, index[value]);
		}
		printf("org_id: \t%s\n", org_id);
		printf("org_in_nid: \t%s\n", org_in_nid);
		if (strncmp(org_in_nid, org_id, strlen(org_id))) /* org_id is not same */
			return 1;
		else
			return 0;
	} else {
		fprintf(stderr, "Invalid nid(not intra/external)\n");
		return -1;
	}
}

/*
 * return 0: time
 * return 1: mac
 */
int idea_mac(char *idea_key)
{
	MYSQL *conn_teledata;
	MYSQL_RES *res_teledata;
	MYSQL_ROW row_teledata;

	char sql_cmd[1024] = {0};
	int ret = 0;

	conn_teledata = mysql_init(NULL);
	if (!conn_teledata) {
		fprintf(stderr, "mysql_init failed\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect
	    (conn_teledata, DATABASE_IP, "root", "YUIOPPOIUY",
	     "cngi", 3306, NULL, 0)) {
		snprintf(sql_cmd, 1024, "SELECT idea_key, idea_type FROM NA_IDEA where now() between start_time and end_time");
		int teledata = mysql_query(conn_teledata, sql_cmd);
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) {
				while ((row_teledata = mysql_fetch_row(res_teledata))) {
					memset(idea_key, 0, sizeof(idea_key));
					strncpy(idea_key, row_teledata[0], strlen(row_teledata[0]));
					if (strcmp(row_teledata[1], "idea_mac") == 0)
						ret = 1;
				}
				mysql_free_result(res_teledata);
			}
		} else
			printf("SELECT error: %s\n", mysql_error(conn_teledata));
	} else {
		fprintf(stderr, "Connection failed\n");
		if (mysql_errno(conn_teledata))
			fprintf(stderr, "Connection error %d: %s\n",
				mysql_errno(conn_teledata),
				mysql_error(conn_teledata));
	}
	mysql_close(conn_teledata);
	return ret;
}

int insert_NA_MACHASH(char *nid, char *mac, char *hmac)
{
	MYSQL *conn_teledata;
	MYSQL_RES *res_teledata;
	MYSQL_ROW row_teledata;

	char sql_cmd[1024] = {0};

	conn_teledata = mysql_init(NULL);
	if (!conn_teledata) {
		fprintf(stderr, "mysql_init failed\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect
	    (conn_teledata, DATABASE_IP, "root", "YUIOPPOIUY",
	     "cngi", 3306, NULL, 0)) {
		snprintf(sql_cmd, 1024, "INSERT into NA_MACHASH values('','%s','%s','',concat('0','%s'),now())", nid, mac, hmac);
		int teledata = mysql_query(conn_teledata, sql_cmd);
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) 
				mysql_free_result(res_teledata);
		} else
			printf("INSERT into NA_MACHASH error: %s\n", mysql_error(conn_teledata));
	} else {
		fprintf(stderr, "Connection failed\n");
		if (mysql_errno(conn_teledata))
			fprintf(stderr, "Connection error %d: %s\n",
				mysql_errno(conn_teledata),
				mysql_error(conn_teledata));
	}
	mysql_close(conn_teledata);
	return 0;
}

int insert_radpostauth(char *nid, char *ip, char *time, char *mac)
{
	MYSQL *conn_teledata;
	MYSQL_RES *res_teledata;
	MYSQL_ROW row_teledata;

	char sql_cmd[1024] = {0};

	conn_teledata = mysql_init(NULL);
	if (!conn_teledata) {
		fprintf(stderr, "mysql_init failed\n");
		exit(EXIT_FAILURE);
	}
	if (mysql_real_connect
	    (conn_teledata, DATABASE_IP, "root", "YUIOPPOIUY",
	     "cngi", 3306, NULL, 0)) {
		/*
		snprintf(sql_cmd, 1024, "INSERT into radpostauth(username, authdate, user_ipv6_address, user_mac)" 
						"values('%s','%s','%s','%s')", nid, time, ip, mac);
						*/
		snprintf(sql_cmd, 1024, "INSERT into radpostauth(username, authdate, user_ipv6_address, user_mac)" 
						"values('%s',now(),'%s','%s')", nid, ip, mac);
		int teledata = mysql_query(conn_teledata, sql_cmd);
		if (!teledata) {
			res_teledata = mysql_use_result(conn_teledata);
			if (res_teledata) 
				mysql_free_result(res_teledata);
		} else
			printf("INSERT into radpostauth error: %s\n", mysql_error(conn_teledata));
	} else {
		fprintf(stderr, "Connection failed\n");
		if (mysql_errno(conn_teledata))
			fprintf(stderr, "Connection error %d: %s\n",
				mysql_errno(conn_teledata),
				mysql_error(conn_teledata));
	}
	mysql_close(conn_teledata);
	return 0;
}
