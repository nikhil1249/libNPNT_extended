/*
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */


#ifdef __cplusplus
extern "C" {
#endif
    /* Declarations of this file */

#include <inc/npnt_internal.h>
#include <npnt.h>
/**
 * @brief   Sets Current Permission Artifact.
 * @details This method consumes peremission artefact in raw format
 *          and sets up npnt structure.
 *
 * @param[in] npnt_handle       npnt handle
 * @param[in] permart           permission json artefact in base64 format as received
 *                              from server
 * @param[in] permart_length    size of permission json artefact in base64 format as received
 *                              from server
 * @param[in] signature         signature of permart in base64 format
 * @param[in] signature_length  length of the signature of permart in base64 format
 *
 * @return           Error id if faillure, 0 if no breach
 * @retval NPNT_INV_ART   Invalid Artefact
 *         NPNT_INV_AUTH  signed by unauthorised entity
 *         NPNT_INV_STATE artefact can't setup in current aircraft state
 *         NPNT_ALREADY_SET artefact already set, free previous artefact first
 * @iclass control_iface
 */
int8_t npnt_set_permart(npnt_s *handle, uint8_t *permart, uint16_t permart_length)
{
    if (!handle)
    {
        return NPNT_UNALLOC_HANDLE;
    }
    int16_t ret = 0;
    //Extract XML from base64 encoded permart
    if (handle->raw_permart)
    {
        return NPNT_ALREADY_SET;
    }

    handle->raw_permart = base64_decode(permart, permart_length, &handle->raw_permart_len);
    if (!handle->raw_permart) {
        return NPNT_PARSE_FAILED;
    }

    //parse XML permart
    handle->parsed_permart = mxmlLoadString(NULL, (char*)handle->raw_permart, MXML_OPAQUE_CALLBACK);
    if (!handle->parsed_permart) {
        return NPNT_PARSE_FAILED;
    }
    //Verify Artifact against Sender's Public Key
    ret = npnt_verify_permart(handle);
    if (ret < 0) {
        return ret;
    }

    ret = 0;
    return ret;
}

//Verify the data contained in parsed XML
int8_t npnt_verify_permart(npnt_s *handle)
{
    char* raw_perm_without_sign;
    char* signed_info;
    const uint8_t* rcvd_digest_value;
    // char *test_str;
    int16_t permission_length, signedinfo_length;
    char digest_value[32];
    const uint8_t* signature = NULL;
    uint8_t* raw_signature = NULL;
    uint16_t signature_len, raw_signature_len;
    uint8_t* base64_digest_value = NULL;
    uint16_t base64_digest_value_len;
    uint16_t curr_ptr = 0, curr_length;
    char last_empty_element[32];
    int8_t ret = 0;

    reset_sha256();

    update_sha256("<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">",
                strlen("<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"));

    signed_info = strstr(handle->raw_permart, "<SignedInfo>") + strlen("<SignedInfo>");

    if (signed_info == NULL) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    signedinfo_length = strstr(handle->raw_permart, "<SignatureValue") - signed_info;
    if (signedinfo_length < 0) {
        ret = NPNT_INV_ART;
        goto fail;
    }

    while (curr_ptr < signedinfo_length) {
        curr_length = 1;
        if (signed_info[curr_ptr] == '<') {
            while((curr_ptr + curr_length) < signedinfo_length) {
                if (signed_info[curr_ptr + curr_length] == ' ') {
                    last_empty_element[curr_length - 1] = '\0';
                    break;
                } else if (signed_info[curr_ptr + curr_length] == '>') {
                    last_empty_element[0] = '\0';
                    break;
                }
                last_empty_element[curr_length - 1] = signed_info[curr_ptr + curr_length];
                curr_length++;
            }
        }

        if (strlen(last_empty_element) != 0) {
            if (signed_info[curr_ptr] == '/') {
                if (signed_info[curr_ptr + 1] == '>') {
                    update_sha256("></", 3);
                    update_sha256(last_empty_element, strlen(last_empty_element));
                    last_empty_element[0] = '\0';
                    curr_ptr += curr_length;
                    continue;
                }
            }
        }

          update_sha256(&signed_info[curr_ptr], curr_length);

        curr_ptr += curr_length;
    }
      final_sha256(digest_value);

    //fetch SignatureValue from xml
    signature = (const uint8_t*)mxmlGetOpaque(mxmlFindElement(handle->parsed_permart, handle->parsed_permart, "SignatureValue", NULL, NULL, MXML_DESCEND));
    if (signature == NULL) {
        ret = NPNT_INV_SIGN;
        goto fail;
    }
    signature_len = strlen(signature);
    raw_signature = base64_decode(signature, signature_len, &raw_signature_len);

    if (npnt_check_authenticity(handle, digest_value, 32, raw_signature, raw_signature_len) <= 0) {
        ret = NPNT_INV_AUTH;
        goto fail;
    }

    //Digest Canonicalised Permission Artifact
    raw_perm_without_sign = strstr(handle->raw_permart, "<UAPermission");
    if (raw_perm_without_sign == NULL) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    permission_length = strstr(handle->raw_permart, "<Signature") - raw_perm_without_sign;
    if (permission_length < 0) {
        ret = NPNT_INV_ART;
        goto fail;
    }
    reset_sha256();
    curr_ptr = 0;
    curr_length = 0;

    //Canonicalise Permission Artefact by converting Empty elements to start-end tag pairs
    while (curr_ptr < permission_length) {
        curr_length = 1;
        if (raw_perm_without_sign[curr_ptr] == '<') {
            while((curr_ptr + curr_length) < permission_length) {
                if (raw_perm_without_sign[curr_ptr + curr_length] == ' ') {
                    last_empty_element[curr_length - 1] = '\0';
                    break;
                } else if (raw_perm_without_sign[curr_ptr + curr_length] == '>') {
                    last_empty_element[0] = '\0';
                    break;
                }
                last_empty_element[curr_length - 1] = raw_perm_without_sign[curr_ptr + curr_length];
                curr_length++;
            }
        }

        if (strlen(last_empty_element) != 0) {
            if (raw_perm_without_sign[curr_ptr] == '/') {
                if (raw_perm_without_sign[curr_ptr + 1] == '>') {
                    update_sha256("></", 3);
                    update_sha256(last_empty_element, strlen(last_empty_element));
                    last_empty_element[0] = '\0';
                    curr_ptr += curr_length;
                    continue;
                }
            }
        }

        update_sha256(&raw_perm_without_sign[curr_ptr], curr_length);

        curr_ptr += curr_length;
    }

    //Skip Signature for Digestion
    raw_perm_without_sign = strstr(handle->raw_permart, "</Signature>") + strlen("</Signature>");
    update_sha256(raw_perm_without_sign, strlen(raw_perm_without_sign));
    final_sha256(digest_value);
    base64_digest_value = base64_encode(digest_value, 32, &base64_digest_value_len);

    //Check Digestion
    rcvd_digest_value = (const uint8_t*)mxmlGetOpaque(mxmlFindElement(handle->parsed_permart, handle->parsed_permart, "DigestValue", NULL, NULL, MXML_DESCEND));

    uint16_t i = 0;
    for (i = 0; i < base64_digest_value_len - 1; i++) {
        if (base64_digest_value[i] != rcvd_digest_value[i]) {
            ret = NPNT_INV_DGST;
            goto fail;
        }
    }

    //base64_digest_value no longer needed
    free(base64_digest_value);
    base64_digest_value = NULL;
fail:
    if (base64_digest_value) {
        free(base64_digest_value);
    }
    return ret;
}

#ifdef __cplusplus
}
#endif


