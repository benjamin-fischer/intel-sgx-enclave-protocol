#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "sgx_trts.h"

int enclave_secret = 1337;

sgx_ecc_state_handle_t ecc_state;
sgx_ec256_private_t Enc_A_private_key;
sgx_ec256_dh_shared_t shared_dh_key;

uint8_t truncated_shared_dh_key[SGX_AESCTR_KEY_SIZE];
const char* PSK_A = "I AM ALICE";
const char* PSK_B = "I AM BOBOB";

uint8_t a = 0; // a is in [0,255]
uint8_t b = 0; // b is in [0,255]
uint8_t separator = 0;

int printf(const char* fmt, ...) {
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t printSecret() {
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}

/*************************
* BEGIN [2. Enclave A generates an ECC key pair]
*************************/
sgx_status_t generate_key_pair(sgx_ec256_public_t* Enc_A_public_key) {

  memset(&Enc_A_private_key, 0, sizeof(Enc_A_private_key));

  sgx_status_t ret_status = sgx_ecc256_open_context(&ecc_state);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  ret_status = sgx_ecc256_create_key_pair(&Enc_A_private_key, Enc_A_public_key, ecc_state);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  return SGX_SUCCESS;
}
/*************************
* END [2. Enclave A generates an ECC key pair]
*************************/

/*************************
* BEGIN [3. Enclave A calculates the shared Diffie-Hellman key]
*************************/ 
sgx_status_t compute_shared_dh_key(sgx_ec256_public_t Enc_B_public_key) {

  memset(&shared_dh_key, 0, sizeof(shared_dh_key));

  sgx_status_t ret_status = sgx_ecc256_compute_shared_dhkey(&Enc_A_private_key, &Enc_B_public_key, &shared_dh_key, ecc_state);
  if (ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  // Truncate the shared DH key to 128 bits
  memcpy(&truncated_shared_dh_key, &shared_dh_key, sizeof(truncated_shared_dh_key));

  return SGX_SUCCESS;
}
/*************************
* END [3. Enclave A calculates the shared Diffie-Hellman key]
*************************/

/*************************
* BEGIN [0. Enclave A computes the encrypted PSK]
*************************/
sgx_status_t get_encrypted_PSK(uint8_t* c, int i) {

  int PSK_A_length = (int) strlen(PSK_A);
  uint8_t PSK_A_uint[PSK_A_length];

  for(int j = 0; j < PSK_A_length; j++) {
    PSK_A_uint[j] = PSK_A[j];
  }

  uint8_t iv[SGX_AESCTR_KEY_SIZE];
  memset(iv, 0, sizeof(iv));

  sgx_status_t ret_status = sgx_aes_ctr_encrypt(&truncated_shared_dh_key, &PSK_A_uint[i], (uint32_t) sizeof(PSK_A_uint[i]), iv, 1, c);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  return SGX_SUCCESS;
}
/*************************
* END [0. Enclave A computes the encrypted PSK]
*************************/

/*************************
* BEGIN [0. Enclave A decrypts and verifies the encrypted PSK of Enclave B]
*************************/
sgx_status_t decrypt_and_check_PSK(uint8_t Enc_B_encrypted_PSK, int i, int* check) {

  uint8_t Enc_B_decrypted_PSK;
  uint8_t iv[SGX_AESCTR_KEY_SIZE];
  memset(iv, 0, sizeof(iv));

  sgx_status_t ret_status = sgx_aes_ctr_decrypt(&truncated_shared_dh_key, &Enc_B_encrypted_PSK, (uint32_t) sizeof(Enc_B_encrypted_PSK), iv, 1, &Enc_B_decrypted_PSK);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  if((char) Enc_B_decrypted_PSK != (char) PSK_B[i]) {
    (*check)++;
  }

  return SGX_SUCCESS;
}
/*************************
* END [0. Enclave A decrypts and verifies the encrypted PSK of Enclave B]
*************************/

/*************************
* BEGIN [4. Enclave A generates and encrypts the challenge]
*************************/
sgx_status_t get_challenge(uint8_t* encrypted_a, uint8_t* encrypted_separator, uint8_t* encrypted_b) {

  sgx_status_t ret_status;
  uint8_t iv[SGX_AESCTR_KEY_SIZE];

  ret_status = sgx_read_rand(&a, 1);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  separator = (uint8_t) ':';

  ret_status = sgx_read_rand(&b, 1);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  /* Debugging */
  // printf("[Enclave A]: a = %u\n", a);
  // printf("[Enclave A]: b = %u\n", b);

  memset(iv, 0, sizeof(iv));
  ret_status = sgx_aes_ctr_encrypt(&truncated_shared_dh_key, &a, (uint32_t) sizeof(a), iv, 1, encrypted_a);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  memset(iv, 0, sizeof(iv));
  ret_status = sgx_aes_ctr_encrypt(&truncated_shared_dh_key, &separator, (uint32_t) sizeof(separator), iv, 1, encrypted_separator);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  memset(iv, 0, sizeof(iv));
  ret_status = sgx_aes_ctr_encrypt(&truncated_shared_dh_key, &b, (uint32_t) sizeof(b), iv, 1, encrypted_b);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  return SGX_SUCCESS;
}
/*************************
* END [4. Enclave A generates and encrypts the challenge]
*************************/

/*************************
* BEGIN [5. Enclave A decrypts and verifies the response of Enclave B]
*************************/
sgx_status_t decrypt_and_check_response(uint8_t encrypted_response, int* verify) {

  uint8_t decrypted_response;
  uint8_t iv[SGX_AESCTR_KEY_SIZE];
  memset(iv, 0, sizeof(iv));

  sgx_status_t ret_status = sgx_aes_ctr_decrypt(&truncated_shared_dh_key, &encrypted_response, (uint32_t) sizeof(encrypted_response), iv, 1, &decrypted_response);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  int sum = (int) a + (int) b;
  int int_response = (int) decrypted_response;
  int response_overflow = int_response + 256;

  if(sum > 255) { // uint8_t overflow
    if(response_overflow != sum) {
      (*verify)++;
    }
    /* Debugging */
    //   else {
    //   printf("[Enclave A]: The provided response MATCHES the sum of a and b!\n");
    //   printf("[Enclave A]: Response\t: %i\n", response_overflow);
    //   printf("[Enclave A]: Sum (a+b)\t: %i\n", sum);
    // }
  } else { // sum in [0,255]
    if(int_response != sum) {
      (*verify)++;
    }
    /* Debugging */
    //   else {
    //   printf("[Enclave A]: The provided response MATCHES the sum of a and b!\n");
    //   printf("[Enclave A]: Response\t: %i\n", int_response);
    //   printf("[Enclave A]: Sum (a+b)\t: %i\n", sum);
    // }
  }

  return SGX_SUCCESS;
}
/*************************
* END [5. Enclave A decrypts and verifies the response of Enclave B]
*************************/



