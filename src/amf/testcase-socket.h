#ifndef AMF_TESTCASE_SOCKET_H
#define AMF_TESTCASE_SOCKET_H


#ifdef __cplusplus
extern "C" {
#endif

#include "context.h"

void intercept_pkt(ogs_pkbuf_t *pkbuf);

#ifdef __cplusplus
}
#endif

#endif /* AMF_TESTCASE_SOCKET_H */
