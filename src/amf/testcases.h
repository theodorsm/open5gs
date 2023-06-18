#ifndef TESTCASES_H
#define TESTCASES_H

#include "context.h"
#include "nas-path.h"

#ifdef __cplusplus
extern "C" {
#endif

ogs_pkbuf_t *testcase_build_security_mode_command(amf_ue_t *amf_ue);
int testcase_deregistration(amf_ue_t *amf_ue);

#ifdef __cplusplus
}
#endif

#endif /* TESTCASES_H */
