#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_printSecret_t {
	sgx_status_t ms_retval;
} ms_printSecret_t;

typedef struct ms_generate_key_pair_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_Enc_B_public_key;
} ms_generate_key_pair_t;

typedef struct ms_compute_shared_dh_key_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t ms_Enc_A_public_key;
} ms_compute_shared_dh_key_t;

typedef struct ms_decrypt_and_check_PSK_t {
	sgx_status_t ms_retval;
	uint8_t ms_Enc_A_encrypted_PSK;
	int ms_i;
	int* ms_check;
} ms_decrypt_and_check_PSK_t;

typedef struct ms_get_encrypted_PSK_t {
	sgx_status_t ms_retval;
	uint8_t* ms_c;
	int ms_i;
} ms_get_encrypted_PSK_t;

typedef struct ms_decrypt_challenge_t {
	sgx_status_t ms_retval;
	uint8_t ms_c1;
	uint8_t ms_c2;
	uint8_t ms_c3;
	uint8_t* ms_decrypted_a;
	uint8_t* ms_decrypted_b;
} ms_decrypt_challenge_t;

typedef struct ms_encrypt_response_t {
	sgx_status_t ms_retval;
	uint8_t* ms_encrypted_response;
	uint8_t ms_decrypted_a;
	uint8_t ms_decrypted_b;
} ms_encrypt_response_t;

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

sgx_status_t generate_key_pair(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* Enc_B_public_key)
{
	sgx_status_t status;
	ms_generate_key_pair_t ms;
	ms.ms_Enc_B_public_key = Enc_B_public_key;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t compute_shared_dh_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t Enc_A_public_key)
{
	sgx_status_t status;
	ms_compute_shared_dh_key_t ms;
	ms.ms_Enc_A_public_key = Enc_A_public_key;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_and_check_PSK(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t Enc_A_encrypted_PSK, int i, int* check)
{
	sgx_status_t status;
	ms_decrypt_and_check_PSK_t ms;
	ms.ms_Enc_A_encrypted_PSK = Enc_A_encrypted_PSK;
	ms.ms_i = i;
	ms.ms_check = check;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_encrypted_PSK(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* c, int i)
{
	sgx_status_t status;
	ms_get_encrypted_PSK_t ms;
	ms.ms_c = c;
	ms.ms_i = i;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t decrypt_challenge(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t c1, uint8_t c2, uint8_t c3, uint8_t* decrypted_a, uint8_t* decrypted_b)
{
	sgx_status_t status;
	ms_decrypt_challenge_t ms;
	ms.ms_c1 = c1;
	ms.ms_c2 = c2;
	ms.ms_c3 = c3;
	ms.ms_decrypted_a = decrypted_a;
	ms.ms_decrypted_b = decrypted_b;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t encrypt_response(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* encrypted_response, uint8_t decrypted_a, uint8_t decrypted_b)
{
	sgx_status_t status;
	ms_encrypt_response_t ms;
	ms.ms_encrypted_response = encrypted_response;
	ms.ms_decrypted_a = decrypted_a;
	ms.ms_decrypted_b = decrypted_b;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

