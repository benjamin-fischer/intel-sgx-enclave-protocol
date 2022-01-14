#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include "sgx_trts.h"

int enclave_secret = 42;

sgx_ecc_state_handle_t ecc_state;
sgx_ec256_private_t Enc_B_private_key;
sgx_ec256_dh_shared_t shared_dh_key;

uint8_t truncated_shared_dh_key[SGX_AESCTR_KEY_SIZE];
const char* PSK_A = "I AM ALICE";
const char* PSK_B = "I AM BOBOB";

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
* BEGIN [2. Enclave B generates an ECC key pair]
*************************/
sgx_status_t generate_key_pair(sgx_ec256_public_t* Enc_B_public_key) {

  memset(&Enc_B_private_key, 0, sizeof(Enc_B_private_key));

  sgx_status_t ret_status = sgx_ecc256_open_context(&ecc_state);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  ret_status = sgx_ecc256_create_key_pair(&Enc_B_private_key, Enc_B_public_key, ecc_state);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  return SGX_SUCCESS;
}
/*************************
* END [2. Enclave B generates an ECC key pair]
*************************/

/*************************
* BEGIN [3. Enclave B calculates the shared Diffie-Hellman key]
*************************/ 
sgx_status_t compute_shared_dh_key(sgx_ec256_public_t Enc_A_public_key){

  memset(&shared_dh_key, 0, sizeof(shared_dh_key));

  sgx_status_t ret_status = sgx_ecc256_compute_shared_dhkey(&Enc_B_private_key, &Enc_A_public_key, &shared_dh_key, ecc_state);
  if (ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  // Truncate the shared DH key to 128 bits
  memcpy(&truncated_shared_dh_key, &shared_dh_key, sizeof(truncated_shared_dh_key));

  return SGX_SUCCESS;
}
/*************************
* END [3. Enclave B calculates the shared Diffie-Hellman key]
*************************/

/*************************
* BEGIN [0. Enclave B decrypts and verifies the encrypted PSK of Enclave A]
*************************/
sgx_status_t decrypt_and_check_PSK(uint8_t Enc_A_encrypted_PSK, int i, int* check) {

  uint8_t Enc_A_decrypted_PSK;
  uint8_t iv[SGX_AESCTR_KEY_SIZE];
  memset(iv, 0, sizeof(iv));

  sgx_status_t ret_status = sgx_aes_ctr_decrypt(&truncated_shared_dh_key, &Enc_A_encrypted_PSK, (uint32_t) sizeof(Enc_A_encrypted_PSK), iv, 1, &Enc_A_decrypted_PSK);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  if((char) Enc_A_decrypted_PSK != (char) PSK_A[i]) {
    (*check)++;
  }

  return SGX_SUCCESS;
}
/*************************
* END [0. Enclave B decrypts and verifies the encrypted PSK of Enclave A]
*************************/

/*************************
* BEGIN [0. Enclave B computes the encrypted PSK]
*************************/
sgx_status_t get_encrypted_PSK(uint8_t* c, int i) {

  int PSK_B_length = (int) strlen(PSK_B);
  uint8_t PSK_B_uint[PSK_B_length];

  for(int j = 0; j < PSK_B_length; j++) {
    PSK_B_uint[j] = PSK_B[j];
  }

  uint8_t iv[SGX_AESCTR_KEY_SIZE];
  memset(iv, 0, sizeof(iv));

  sgx_status_t ret_status = sgx_aes_ctr_encrypt(&truncated_shared_dh_key, &PSK_B_uint[i], (uint32_t) sizeof(PSK_B_uint[i]), iv, 1, c);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  return SGX_SUCCESS;
}
/*************************
* END [0. Enclave B computes the encrypted PSK]
*************************/

/*************************
* BEGIN [6. Enclave B decrypts the challenge of Enclave A]
*************************/
sgx_status_t decrypt_challenge(uint8_t c1, uint8_t c2, uint8_t c3, uint8_t* decrypted_a, uint8_t* decrypted_b) {

  sgx_status_t ret_status;
  uint8_t iv[SGX_AESCTR_KEY_SIZE];
  uint8_t decrypted_separator;

  memset(iv, 0, sizeof(iv));
  ret_status = sgx_aes_ctr_decrypt(&truncated_shared_dh_key, &c1, (uint32_t) sizeof(c1), iv, 1, decrypted_a);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  memset(iv, 0, sizeof(iv));
  ret_status = sgx_aes_ctr_decrypt(&truncated_shared_dh_key, &c2, (uint32_t) sizeof(c2), iv, 1, &decrypted_separator);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  if((char) decrypted_separator != ':') {
    printf("[Enclave B]: Invalid separator in decrypted challenge.\n");
  }

  memset(iv, 0, sizeof(iv));
  ret_status = sgx_aes_ctr_decrypt(&truncated_shared_dh_key, &c3, (uint32_t) sizeof(c3), iv, 1, decrypted_b);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  return SGX_SUCCESS;
}
/*************************
* END [6. Enclave B decrypts the challenge of Enclave A]
*************************/

/*************************
* BEGIN [7. Enclave B computes and encrypts the response]
*************************/
sgx_status_t encrypt_response(uint8_t* encrypted_response, uint8_t decrypted_a, uint8_t decrypted_b) {

  uint8_t iv[SGX_AESCTR_KEY_SIZE];
  memset(iv, 0, sizeof(iv));

  uint8_t response = (uint8_t) (decrypted_a + decrypted_b);

  sgx_status_t ret_status = sgx_aes_ctr_encrypt(&truncated_shared_dh_key, &response, (uint32_t) sizeof(response), iv, 1, encrypted_response);
  if(ret_status != SGX_SUCCESS) {
    return ret_status;
  }

  return SGX_SUCCESS;
}
/*************************
* END [7. Enclave B computes and encrypts the response]
*************************/



