#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_printSecret_t {
	sgx_status_t ms_retval;
} ms_printSecret_t;

typedef struct ms_generate_key_pair_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_Enc_A_public_key;
} ms_generate_key_pair_t;

typedef struct ms_compute_shared_dh_key_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t ms_Enc_B_public_key;
} ms_compute_shared_dh_key_t;

typedef struct ms_get_encrypted_PSK_t {
	sgx_status_t ms_retval;
	uint8_t* ms_c;
	int ms_i;
} ms_get_encrypted_PSK_t;

typedef struct ms_decrypt_and_check_PSK_t {
	sgx_status_t ms_retval;
	uint8_t ms_Enc_B_encrypted_PSK;
	int ms_i;
	int* ms_check;
} ms_decrypt_and_check_PSK_t;

typedef struct ms_get_challenge_t {
	sgx_status_t ms_retval;
	uint8_t* ms_encrypted_a;
	uint8_t* ms_encrypted_separator;
	uint8_t* ms_encrypted_b;
} ms_get_challenge_t;

typedef struct ms_decrypt_and_check_response_t {
	sgx_status_t ms_retval;
	uint8_t ms_encrypted_response;
	int* ms_verify;
} ms_decrypt_and_check_response_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t printSecret(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_printSecret_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t generate_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* Enc_A_public_key)
{
	sgx_status_t status;
	ms_generate_key_pair_t ms;
	ms.ms_Enc_A_public_key = Enc_A_public_key;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t compute_shared_dh_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t Enc_B_public_key)
{
	sgx_status_t status;
	ms_compute_shared_dh_key_t ms;
	ms.ms_Enc_B_public_key = Enc_B_public_key;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_encrypted_PSK(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* c, int i)
{
	sgx_status_t status;
	ms_get_encrypted_PSK_t ms;
	ms.ms_c = c;
	ms.ms_i = i;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_and_check_PSK(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t Enc_B_encrypted_PSK, int i, int* check)
{
	sgx_status_t status;
	ms_decrypt_and_check_PSK_t ms;
	ms.ms_Enc_B_encrypted_PSK = Enc_B_encrypted_PSK;
	ms.ms_i = i;
	ms.ms_check = check;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_challenge(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* encrypted_a, uint8_t* encrypted_separator, uint8_t* encrypted_b)
{
	sgx_status_t status;
	ms_get_challenge_t ms;
	ms.ms_encrypted_a = encrypted_a;
	ms.ms_encrypted_separator = encrypted_separator;
	ms.ms_encrypted_b = encrypted_b;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_and_check_response(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t encrypted_response, int* verify)
{
	sgx_status_t status;
	ms_decrypt_and_check_response_t ms;
	ms.ms_encrypted_response = encrypted_response;
	ms.ms_verify = verify;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

