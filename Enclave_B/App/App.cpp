#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h> /* bind, listen, accept, close */
#include <arpa/inet.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#define DEFAULT_PSK_LENGTH 10 // strlen("I AM ALICE") == strlen("I AM BOBOB") == 10
#define CHALLENGE_RESPONSE_ITERATION_NUM 20

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {

    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Enclave initialization: Call sgx_create_enclave to initialize an enclave instance */
int initialize_enclave(void) {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

/* OCALL functions */
void ocall_print_string(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate the input string to prevent buffer overflow */
    printf("%s", str);
}

/* Establishes a socket connection with App A. Based on https://www.geeksforgeeks.org/socket-programming-cc/ */
int initiate_communication(int* App_A_socket_fd, char *argv[]) {

    struct sockaddr_in App_B_address;
    memset(&App_B_address, 0, sizeof(App_B_address));

    int App_B_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(App_B_socket_fd < 0) {
        printf("ERROR: Failed to create socket.\n");
        return -1;
    }

    App_B_address.sin_family = AF_INET;
    App_B_address.sin_addr.s_addr = inet_addr(argv[1]);
    App_B_address.sin_port = htons((uint16_t) atoi(argv[2]));

    if(bind(App_B_socket_fd, (struct sockaddr *) &App_B_address, sizeof(App_B_address)) < 0){
        printf("ERROR: Failed to bind socket.\n");
        close(App_B_socket_fd);
        return -1;
    }

    if((listen(App_B_socket_fd, 20)) < 0){
        printf("ERROR: Failed to listen for connections.\n");
        close(App_B_socket_fd);
        return -1;
    }

    struct sockaddr_in App_A_address;
    unsigned int App_A_address_len = sizeof(App_A_address);
    *App_A_socket_fd = accept(App_B_socket_fd, (struct sockaddr *) &App_A_address, (socklen_t *) &App_A_address_len);
    if(*App_A_socket_fd < 0) {
        printf("ERROR: Cannot connect to App A.\n");
        close(App_B_socket_fd);
        return -1;
    }

    return App_B_socket_fd;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {

    /* Checks argument number */
    if(argc != 3){
      printf("Usage\t: ./app HOST_IP PORT\n");
      printf("Example\t: ./app 127.0.0.1 4567\n");
      return -1;
    }

    printf("[App B]: ######## PROTOCOL BEGINS ########\n");
    printf("\n");

    sgx_status_t sgx_status;
    sgx_status_t ret_status;    

    /* Initializes Enclave B */
    if(initialize_enclave() < 0){
        printf("[App B]: Enclave B FAILED to be created.\n");
        return -1;
    } else {
        printf("[App B]: Enclave B was SUCCESSFULLY created.\n");
    }
    
    /*************************
    * BEGIN [2. Enclave B generates an ECC key pair]
    *************************/
    sgx_ec256_public_t Enc_B_public_key;
    memset(&Enc_B_public_key, 0, sizeof(Enc_B_public_key));

    ret_status = generate_key_pair(global_eid, &sgx_status, &Enc_B_public_key);
    if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS){
      printf("[App B]: Enclave B FAILED to generate an ECC key pair.\n");
      print_error_message(sgx_status);
      print_error_message(ret_status);
      return -1;
    } else {
      printf("[App B]: Enclave B SUCCESSFULLY generated an ECC key pair.\n");
    }
    /*************************
    * END [2. Enclave B generates an ECC key pair]
    *************************/

    /* Establishes a socket connection with Application A (Client) */
    int App_A_socket_fd;
    int App_B_socket_fd = initiate_communication(&App_A_socket_fd, argv);
    if(App_B_socket_fd < 0) {
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App B]: SUCCESSFUL connection with App A.\n");
    }

    /*************************
    * BEGIN [1. App B receives the ECC public key of Enclave A from App A]
    *************************/ 
    sgx_ec256_public_t Enc_A_public_key;
    memset(&Enc_A_public_key, 0, sizeof(Enc_A_public_key));

    if(read(App_A_socket_fd, Enc_A_public_key.gx, SGX_ECP256_KEY_SIZE) < 0) {
        printf("[App B]: FAILED reception of the ECC public key (g^x) of Enclave A.\n");
        close(App_B_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App B]: SUCCESSFUL reception of the ECC public key (g^x) of Enclave A.\n");
    }
    if(read(App_A_socket_fd, Enc_A_public_key.gy, SGX_ECP256_KEY_SIZE) < 0) {
        printf("[App B]: FAILED reception of the ECC public key (g^y) of Enclave A.\n");
        close(App_B_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App B]: SUCCESSFUL reception of the ECC public key (g^y) of Enclave A.\n");
    }
    /*************************
    * END [1. App B receives the ECC public key of Enclave A from App A]
    *************************/

    /*************************
    * BEGIN [3. Enclave B calculates the shared Diffie-Hellman key]
    *************************/ 
    ret_status = compute_shared_dh_key(global_eid, &sgx_status, Enc_A_public_key);
    if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
      printf("[App B]: Enclave B FAILED to compute the shared DH key.\n");
      print_error_message(sgx_status);
      print_error_message(ret_status);
      close(App_B_socket_fd);
      sgx_destroy_enclave(global_eid);
      return -1;
    } else {
       printf("[App B]: Enclave B SUCCESSFULLY computed the shared DH key.\n");
    }
    /*************************
    * END [3. Enclave B calculates the shared Diffie-Hellman key]
    *************************/

    /*************************
    * BEGIN [1. App B sends the ECC public key of Enclave B to App A]
    *************************/ 
    if(write(App_A_socket_fd, Enc_B_public_key.gx, SGX_ECP256_KEY_SIZE) < SGX_ECP256_KEY_SIZE) {
        printf("[App B]: FAILED transmission of the ECC public key (g^x) of Enclave B.\n");
        close(App_B_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App B]: SUCCESSFUL transmission of the ECC public key (g^x) of Enclave B.\n");
    }
    if(write(App_A_socket_fd, Enc_B_public_key.gy, SGX_ECP256_KEY_SIZE) < SGX_ECP256_KEY_SIZE) {
        printf("[App B]: FAILED transmission of the ECC public key (g^y) of Enclave B.\n");
        close(App_B_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App B]: SUCCESSFUL transmission of the ECC public key (g^y) of Enclave B.\n");
    }
    /*************************
    * END [1. App B sends the ECC public key of Enclave B to App A]
    *************************/

    /*************************
    * BEGIN [1. App B receives the encrypted PSK of Enclave A from App A]
    *************************/ 
    uint8_t Enc_A_encrypted_PSK[DEFAULT_PSK_LENGTH];
    if(read(App_A_socket_fd, &Enc_A_encrypted_PSK, sizeof(Enc_A_encrypted_PSK)) < 0) {
        printf("[App B]: FAILED reception of the encrypted PSK of Enclave A.\n");
        close(App_B_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App B]: SUCCESSFUL reception of the encrypted PSK of Enclave A.\n");
    }
    /*************************
    * END [1. App B receives the encrypted PSK of Enclave A from App A]
    *************************/

    /*************************
    * BEGIN [0. Enclave B decrypts and verifies the encrypted PSK of Enclave A]
    *************************/
    int check = 0;
    for(int i = 0; i < DEFAULT_PSK_LENGTH; i++) {
        ret_status = decrypt_and_check_PSK(global_eid, &sgx_status, Enc_A_encrypted_PSK[i], i, &check);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_B_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        }
    }
    if(check == 0) {
        printf("[App B]: The decrypted PSK MATCHES the local PSK of Enclave A.\n");
    } else {
        printf("[App B]: The decrypted PSK DOES NOT MATCH the local PSK of Enclave A.\n");
    }

    /*************************
    * END [0. Enclave B decrypts and verifies the encrypted PSK of Enclave A]
    *************************/

    /*************************
    * BEGIN [0. Enclave B computes the encrypted PSK]
    *************************/
    uint8_t c;
    uint8_t ciphertext[DEFAULT_PSK_LENGTH];
    for(int i = 0; i < DEFAULT_PSK_LENGTH; i++) {
        ret_status = get_encrypted_PSK(global_eid, &sgx_status, &c, i);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            printf("[App B]: Enclave B FAILED to encrypt the PSK.\n");
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_B_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        }
        ciphertext[i] = c;
    }
    printf("[App B]: Enclave B SUCCESSFULLY encrypted the PSK.\n");
    /*************************
    * END [0. Enclave B computes the encrypted PSK]
    *************************/

    /*************************
    * BEGIN [1. App B sends the encrypted PSK of Enclave B to App A]
    *************************/ 
    if(write(App_A_socket_fd, &ciphertext, sizeof(ciphertext)) < (int) sizeof(ciphertext)) {
        printf("[App B]: FAILED transmission of the encrypted PSK of Enclave B.\n");
        close(App_B_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App B]: SUCCESSFUL transmission of the encrypted PSK of Enclave B.\n");
    }
    /*************************
    * END [1. App B sends the encrypted PSK of Enclave B to App A]
    *************************/

    for(int i = 0; i < CHALLENGE_RESPONSE_ITERATION_NUM; i++) {
        printf("\n");
        printf("[App B]: ***** Challenge-Response N°%i *****\n", i+1);
        /*************************
        * BEGIN [1. App B receives the challenge from App A]
        *************************/ 
        uint8_t challenge[3]; // challenge = AES-CTR('a' || ':' || 'b')
        if(read(App_A_socket_fd, &challenge, sizeof(challenge)) < 0) {
            printf("[App B]: FAILED reception of the challenge.\n");
            close(App_B_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        } else {
            printf("[App B]: SUCCESSFUL reception of the challenge.\n");
        }
        /*************************
        * END [1. App B receives the challenge from App A]
        *************************/

        /*************************
        * BEGIN [6. Enclave B decrypts the challenge of Enclave A]
        *************************/
        uint8_t decrypted_a;
        uint8_t decrypted_b;
        ret_status = decrypt_challenge(global_eid, &sgx_status, challenge[0], challenge[1], challenge[2], &decrypted_a, &decrypted_b);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            printf("[App B]: Enclave B FAILED to decrypt the challenge.\n");
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_B_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        } else {
            printf("[App B]: Enclave B SUCCESSFULLY decrypted the challenge.\n");
        }
        /*************************
        * END [6. Enclave B decrypts the challenge of Enclave A]
        *************************/

        /*************************
        * BEGIN [7. Enclave B computes and encrypts the response]
        *************************/
        uint8_t encrypted_response;
        ret_status = encrypt_response(global_eid, &sgx_status, &encrypted_response, decrypted_a, decrypted_b);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            printf("[App B]: Enclave B FAILED to encrypt the response.\n");
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_B_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        } else {
            printf("[App B]: Enclave B SUCCESSFULLY encrypted the response.\n");
        }
        /*************************
        * END [7. Enclave B computes and encrypts the response]
        *************************/

        /*************************
        * BEGIN [1. App B sends the encrypted response to App A]
        *************************/
        if(write(App_A_socket_fd, &encrypted_response, sizeof(encrypted_response)) < (int) sizeof(encrypted_response)) {
            printf("[App B]: FAILED transmission of the encrypted response.\n");
            close(App_B_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        } else {
            printf("[App B]: SUCCESSFUL transmission of the encrypted response.\n");
        }
        /*************************
        * END [1. App B sends the encrypted response to App A]
        *************************/
    }

    /* Terminates connection */
    close(App_B_socket_fd);
    /* Enclave B destruction */
    sgx_destroy_enclave(global_eid);
    
    printf("[App B]: Enclave B destroyed.\n");
    return 0;

}

