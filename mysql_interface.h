/*
 * File: mysql_interface.h
 * -----------------------
 * Description: You can modify the db's IP at this.
 *
 * Author: Artist, haoj@cernet.com
 *
 * Date: May 30, 2015
 *
 */

#include <mysql/mysql.h>

#define DATABASE_IP	"127.0.0.1"

int query_nid(char *nid);
int update_nonce(char *nid, int nonce);
int auth_passwdnonce(char *nid, char *digest);
int intra_or_external(char *nid);
int idea_mac(char *idea_key);
int insert_NA_MACHASH(char *nid, char *mac, char *hmac);
int insert_radpostauth(char *nid, char *ip, char *time, char *mac);
