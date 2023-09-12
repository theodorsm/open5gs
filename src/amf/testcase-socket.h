#ifndef AMF_TESTCASE_SOCKET_H
#define AMF_TESTCASE_SOCKET_H


#ifdef __cplusplus
extern "C" {
#endif

#include "context.h"

#define TESTCASE_MODIFY_FALSE 0
#define TESTCASE_MODIFY_PLAIN 1
#define TESTCASE_MODIFY_ENC 2

void create_client_socket(int *client_socket);
void get_supi(char *supi);
int send_msg_type(uint8_t type);
void modify_msg(ogs_pkbuf_t *pkbuf);
bool testcase_enabled(char *supi);

#ifdef __cplusplus
}
#endif

#endif /* AMF_TESTCASE_SOCKET_H */
