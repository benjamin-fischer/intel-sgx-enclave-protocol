#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t printSecret(void);
sgx_status_t generate_key_pair(sgx_ec256_public_t* Enc_A_public_key);
sgx_status_t compute_shared_dh_key(sgx_ec256_public_t Enc_B_public_key);
sgx_status_t get_encrypted_PSK(uint8_t* c, int i);
sgx_status_t decrypt_and_check_PSK(uint8_t Enc_B_encrypted_PSK, int i, int* check);
sgx_status_t get_challenge(uint8_t* encrypted_a, uint8_t* encrypted_separator, uint8_t* encrypted_b);
sgx_status_t decrypt_and_check_response(uint8_t encrypted_response, int* verify);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
