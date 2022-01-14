#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t printSecret(sgx_enclave_id_t eid, sgx_status_t* retval);
sgx_status_t generate_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* Enc_B_public_key);
sgx_status_t compute_shared_dh_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t Enc_A_public_key);
sgx_status_t decrypt_and_check_PSK(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t Enc_A_encrypted_PSK, int i, int* check);
sgx_status_t get_encrypted_PSK(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* c, int i);
sgx_status_t decrypt_challenge(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t c1, uint8_t c2, uint8_t c3, uint8_t* decrypted_a, uint8_t* decrypted_b);
sgx_status_t encrypt_response(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* encrypted_response, uint8_t decrypted_a, uint8_t decrypted_b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
