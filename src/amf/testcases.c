#include "nas-security.h"
#include "gmm-build.h"
#include "amf-sm.h"
#include "testcases.h"

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __gmm_log_domain

int enc_alg = 0;

ogs_pkbuf_t *testcase_build_security_mode_command(amf_ue_t *amf_ue)
{
    ogs_nas_5gs_message_t message;
    ogs_nas_5gs_security_mode_command_t *security_mode_command =
        &message.gmm.security_mode_command;
    ogs_nas_security_algorithms_t *selected_nas_security_algorithms =
        &security_mode_command->selected_nas_security_algorithms;
    ogs_nas_key_set_identifier_t *ngksi = &security_mode_command->ngksi;
    ogs_nas_ue_security_capability_t *replayed_ue_security_capabilities =
        &security_mode_command->replayed_ue_security_capabilities;
    ogs_nas_imeisv_request_t *imeisv_request =
        &security_mode_command->imeisv_request;
    ogs_nas_additional_5g_security_information_t
        *additional_security_information =
            &security_mode_command->additional_security_information;

    ogs_assert(amf_ue);

    memset(&message, 0, sizeof(message));
    message.h.security_header_type =
        OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT;
    message.h.extended_protocol_discriminator =
        OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;

    message.gmm.h.extended_protocol_discriminator =
        OGS_NAS_EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM;
    message.gmm.h.message_type = OGS_NAS_5GS_SECURITY_MODE_COMMAND;

    amf_ue->selected_int_algorithm = 1;
    amf_ue->selected_enc_algorithm = enc_alg;
    enc_alg++;

    selected_nas_security_algorithms->type_of_integrity_protection_algorithm =
        amf_ue->selected_int_algorithm;
    selected_nas_security_algorithms->type_of_ciphering_algorithm =
        amf_ue->selected_enc_algorithm;

    ngksi->tsc = amf_ue->nas.amf.tsc;
    ngksi->value = amf_ue->nas.amf.ksi;

    replayed_ue_security_capabilities->nr_ea =
        amf_ue->ue_security_capability.nr_ea;
    replayed_ue_security_capabilities->nr_ia =
        amf_ue->ue_security_capability.nr_ia;
    replayed_ue_security_capabilities->eutra_ea =
        amf_ue->ue_security_capability.eutra_ea;
    replayed_ue_security_capabilities->eutra_ia =
        amf_ue->ue_security_capability.eutra_ia;

    replayed_ue_security_capabilities->length =
        sizeof(replayed_ue_security_capabilities->nr_ea) +
        sizeof(replayed_ue_security_capabilities->nr_ia);
    if (replayed_ue_security_capabilities->eutra_ea ||
        replayed_ue_security_capabilities->eutra_ia)
        replayed_ue_security_capabilities->length =
            sizeof(replayed_ue_security_capabilities->nr_ea) +
            sizeof(replayed_ue_security_capabilities->nr_ia) +
            sizeof(replayed_ue_security_capabilities->eutra_ea) +
            sizeof(replayed_ue_security_capabilities->eutra_ia);
    ogs_debug("    Replayed UE SEC[LEN:%d NEA:0x%x NIA:0x%x EEA:0x%x EIA:0x%x",
            replayed_ue_security_capabilities->length,
            replayed_ue_security_capabilities->nr_ea,
            replayed_ue_security_capabilities->nr_ia,
            replayed_ue_security_capabilities->eutra_ea,
            replayed_ue_security_capabilities->eutra_ia);
    ogs_debug("    Selected[Integrity:0x%x Encrypt:0x%x]",
            amf_ue->selected_int_algorithm, amf_ue->selected_enc_algorithm);

    security_mode_command->presencemask |=
        OGS_NAS_5GS_SECURITY_MODE_COMMAND_IMEISV_REQUEST_PRESENT;
    imeisv_request->type = OGS_NAS_IMEISV_TYPE;
    imeisv_request->value = OGS_NAS_IMEISV_REQUESTED;

    security_mode_command->presencemask |= OGS_NAS_5GS_SECURITY_MODE_COMMAND_ADDITIONAL_5G_SECURITY_INFORMATION_PRESENT;
    additional_security_information->length = 1;
    additional_security_information->
        retransmission_of_initial_nas_message_request = 1;

    if (amf_ue->selected_int_algorithm == OGS_NAS_SECURITY_ALGORITHMS_EIA0) {
        ogs_error("Encrypt[0x%x] can be skipped with NEA0, "
            "but Integrity[0x%x] cannot be bypassed with NIA0",
            amf_ue->selected_enc_algorithm, amf_ue->selected_int_algorithm);
        return NULL;
    }

    ogs_kdf_nas_5gs(OGS_KDF_NAS_INT_ALG, amf_ue->selected_int_algorithm,
            amf_ue->kamf, amf_ue->knas_int);
    ogs_kdf_nas_5gs(OGS_KDF_NAS_ENC_ALG, amf_ue->selected_enc_algorithm,
            amf_ue->kamf, amf_ue->knas_enc);

    return nas_5gs_security_encode(amf_ue, &message);
}
