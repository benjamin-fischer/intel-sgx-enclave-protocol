#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_printSecret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_printSecret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_printSecret_t* ms = SGX_CAST(ms_printSecret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = printSecret();


	return status;
}

static sgx_status_t SGX_CDECL sgx_generate_key_pair(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_key_pair_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_key_pair_t* ms = SGX_CAST(ms_generate_key_pair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_Enc_A_public_key = ms->ms_Enc_A_public_key;
	size_t _len_Enc_A_public_key = sizeof(sgx_ec256_public_t);
	sgx_ec256_public_t* _in_Enc_A_public_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_Enc_A_public_key, _len_Enc_A_public_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_Enc_A_public_key != NULL && _len_Enc_A_public_key != 0) {
		if ((_in_Enc_A_public_key = (sgx_ec256_public_t*)malloc(_len_Enc_A_public_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_Enc_A_public_key, 0, _len_Enc_A_public_key);
	}

	ms->ms_retval = generate_key_pair(_in_Enc_A_public_key);
	if (_in_Enc_A_public_key) {
		if (memcpy_s(_tmp_Enc_A_public_key, _len_Enc_A_public_key, _in_Enc_A_public_key, _len_Enc_A_public_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_Enc_A_public_key) free(_in_Enc_A_public_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_compute_shared_dh_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_compute_shared_dh_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_compute_shared_dh_key_t* ms = SGX_CAST(ms_compute_shared_dh_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = compute_shared_dh_key(ms->ms_Enc_B_public_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_encrypted_PSK(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_encrypted_PSK_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_encrypted_PSK_t* ms = SGX_CAST(ms_get_encrypted_PSK_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_c = ms->ms_c;
	size_t _len_c = sizeof(uint8_t);
	uint8_t* _in_c = NULL;

	CHECK_UNIQUE_POINTER(_tmp_c, _len_c);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_c != NULL && _len_c != 0) {
		if ( _len_c % sizeof(*_tmp_c) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_c = (uint8_t*)malloc(_len_c)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_c, 0, _len_c);
	}

	ms->ms_retval = get_encrypted_PSK(_in_c, ms->ms_i);
	if (_in_c) {
		if (memcpy_s(_tmp_c, _len_c, _in_c, _len_c)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_c) free(_in_c);
	return status;
}

static sgx_status_t SGX_CDECL sgx_decrypt_and_check_PSK(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decrypt_and_check_PSK_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decrypt_and_check_PSK_t* ms = SGX_CAST(ms_decrypt_and_check_PSK_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_check = ms->ms_check;
	size_t _len_check = sizeof(int);
	int* _in_check = NULL;

	CHECK_UNIQUE_POINTER(_tmp_check, _len_check);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_check != NULL && _len_check != 0) {
		if ( _len_check % sizeof(*_tmp_check) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_check = (int*)malloc(_len_check)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_check, 0, _len_check);
	}

	ms->ms_retval = decrypt_and_check_PSK(ms->ms_Enc_B_encrypted_PSK, ms->ms_i, _in_check);
	if (_in_check) {
		if (memcpy_s(_tmp_check, _len_check, _in_check, _len_check)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_check) free(_in_check);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_challenge(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_challenge_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_challenge_t* ms = SGX_CAST(ms_get_challenge_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_encrypted_a = ms->ms_encrypted_a;
	size_t _len_encrypted_a = sizeof(uint8_t);
	uint8_t* _in_encrypted_a = NULL;
	uint8_t* _tmp_encrypted_separator = ms->ms_encrypted_separator;
	size_t _len_encrypted_separator = sizeof(uint8_t);
	uint8_t* _in_encrypted_separator = NULL;
	uint8_t* _tmp_encrypted_b = ms->ms_encrypted_b;
	size_t _len_encrypted_b = sizeof(uint8_t);
	uint8_t* _in_encrypted_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_encrypted_a, _len_encrypted_a);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_separator, _len_encrypted_separator);
	CHECK_UNIQUE_POINTER(_tmp_encrypted_b, _len_encrypted_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_encrypted_a != NULL && _len_encrypted_a != 0) {
		if ( _len_encrypted_a % sizeof(*_tmp_encrypted_a) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_a = (uint8_t*)malloc(_len_encrypted_a)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_a, 0, _len_encrypted_a);
	}
	if (_tmp_encrypted_separator != NULL && _len_encrypted_separator != 0) {
		if ( _len_encrypted_separator % sizeof(*_tmp_encrypted_separator) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_separator = (uint8_t*)malloc(_len_encrypted_separator)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_separator, 0, _len_encrypted_separator);
	}
	if (_tmp_encrypted_b != NULL && _len_encrypted_b != 0) {
		if ( _len_encrypted_b % sizeof(*_tmp_encrypted_b) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_encrypted_b = (uint8_t*)malloc(_len_encrypted_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_encrypted_b, 0, _len_encrypted_b);
	}

	ms->ms_retval = get_challenge(_in_encrypted_a, _in_encrypted_separator, _in_encrypted_b);
	if (_in_encrypted_a) {
		if (memcpy_s(_tmp_encrypted_a, _len_encrypted_a, _in_encrypted_a, _len_encrypted_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_encrypted_separator) {
		if (memcpy_s(_tmp_encrypted_separator, _len_encrypted_separator, _in_encrypted_separator, _len_encrypted_separator)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_encrypted_b) {
		if (memcpy_s(_tmp_encrypted_b, _len_encrypted_b, _in_encrypted_b, _len_encrypted_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_encrypted_a) free(_in_encrypted_a);
	if (_in_encrypted_separator) free(_in_encrypted_separator);
	if (_in_encrypted_b) free(_in_encrypted_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_decrypt_and_check_response(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decrypt_and_check_response_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decrypt_and_check_response_t* ms = SGX_CAST(ms_decrypt_and_check_response_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_verify = ms->ms_verify;
	size_t _len_verify = sizeof(int);
	int* _in_verify = NULL;

	CHECK_UNIQUE_POINTER(_tmp_verify, _len_verify);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_verify != NULL && _len_verify != 0) {
		if ( _len_verify % sizeof(*_tmp_verify) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_verify = (int*)malloc(_len_verify)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_verify, 0, _len_verify);
	}

	ms->ms_retval = decrypt_and_check_response(ms->ms_encrypted_response, _in_verify);
	if (_in_verify) {
		if (memcpy_s(_tmp_verify, _len_verify, _in_verify, _len_verify)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_verify) free(_in_verify);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_printSecret, 0, 0},
		{(void*)(uintptr_t)sgx_generate_key_pair, 0, 0},
		{(void*)(uintptr_t)sgx_compute_shared_dh_key, 0, 0},
		{(void*)(uintptr_t)sgx_get_encrypted_PSK, 0, 0},
		{(void*)(uintptr_t)sgx_decrypt_and_check_PSK, 0, 0},
		{(void*)(uintptr_t)sgx_get_challenge, 0, 0},
		{(void*)(uintptr_t)sgx_decrypt_and_check_response, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][7];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

