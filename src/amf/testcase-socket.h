#ifndef AMF_TESTCASE_SOCKET_H
#define AMF_TESTCASE_SOCKET_H


#ifdef __cplusplus
extern "C" {
#endif

#include "context.h"

void intercept_pkt(ogs_pkbuf_t *pkbuf);
int get_enc_alg(void);
int get_int_alg(void);
void send_res(bool complete, ogs_nas_5gmm_cause_t cause);
void send_release_complete(void);

#ifdef __cplusplus
}
#endif

#endif /* AMF_TESTCASE_SOCKET_H */
