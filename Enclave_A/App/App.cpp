#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h> /* socket, connect, close */
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
    const char   *msg;
    const char   *sug; /* Suggestion */
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

    for(idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if(idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Enclave initialization: Call sgx_create_enclave to initialize an enclave instance */
int initialize_enclave(void) {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if(ret != SGX_SUCCESS) {
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

/* Establishes a socket connection with App B. Based on https://www.geeksforgeeks.org/socket-programming-cc/ */
int initiate_communication(char *argv[]) {

    struct sockaddr_in App_B_address;
    memset(&App_B_address, 0, sizeof(App_B_address));

    int App_A_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(App_A_socket_fd < 0) {
        printf("FAILURE: Socket creation.\n");
        return -1;
    }

    App_B_address.sin_family = AF_INET;
    App_B_address.sin_addr.s_addr = inet_addr(argv[1]);
    App_B_address.sin_port = htons((uint16_t) atoi(argv[2]));

    int attempts = 30;
    while(attempts > 0) {
        if(connect(App_A_socket_fd, (struct sockaddr *) &App_B_address, sizeof(App_B_address)) == 0) {
            break;
        }
        attempts -= 1;
        sleep(1);
    }

    if(attempts == 0) {
        printf("FAILURE: Cannot connect to App B.\n");
        close(App_A_socket_fd);
        return -1;
    }

    return App_A_socket_fd;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {

    /* Checks argument number */
    if(argc != 3){
      printf("Usage\t: ./app HOST_IP PORT\n");
      printf("Example\t: ./app 127.0.0.1 4567\n");
      return -1;
    }

    printf("[App A]: ######## PROTOCOL BEGINS ########\n");
    printf("\n");

    sgx_status_t sgx_status;
    sgx_status_t ret_status;    

    /* Initializes Enclave A */
    if(initialize_enclave() < 0){
        printf("[App A]: Enclave A FAILED to be created.\n");
        return -1;
    } else {
        printf("[App A]: Enclave A was SUCCESSFULLY created.\n");
    }
    
    /*************************
    * BEGIN [2. Enclave A generates an ECC key pair]
    *************************/
    sgx_ec256_public_t App_A_public_key;
    memset(&App_A_public_key, 0, sizeof(App_A_public_key));

    ret_status = generate_key_pair(global_eid, &sgx_status, &App_A_public_key);
    if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS){
      printf("[App A]: Enclave A FAILED to generate an ECC key pair.\n");
      print_error_message(sgx_status);
      print_error_message(ret_status);
      return -1;
    } else {
      printf("[App A]: Enclave A SUCCESSFULLY generated an ECC key pair.\n");
    }
    /*************************
    * END [2. Enclave A generates an ECC key pair]
    *************************/

    /* Establishes a socket connection with App B */
    int App_A_socket_fd = initiate_communication(argv);
    if(App_A_socket_fd < 0) {
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App A]: SUCCESSFUL connection with App B.\n");
    }

    /*************************
    * BEGIN [1. App A sends the ECC public key of Enclave A to App B]
    *************************/ 
    if(write(App_A_socket_fd, App_A_public_key.gx, SGX_ECP256_KEY_SIZE) < SGX_ECP256_KEY_SIZE) {
        printf("[App A]: FAILED transmission of the ECC public key (g^x) of Enclave A.\n");
        close(App_A_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App A]: SUCCESSFUL transmission of the ECC public key (g^x) of Enclave A.\n");
    }
    if(write(App_A_socket_fd, App_A_public_key.gy, SGX_ECP256_KEY_SIZE) < SGX_ECP256_KEY_SIZE) {
        printf("[App A]: FAILED transmission of the ECC public key (g^y) of Enclave A.\n");
        close(App_A_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App A]: SUCCESSFUL transmission of the ECC public key (g^y) of Enclave A.\n");
    }
    /*************************
    * END [1. App A sends the ECC public key of Enclave A to App B]
    *************************/

    /*************************
    * BEGIN [1. App A receives the ECC public key of Enclave B from App B]
    *************************/ 
    sgx_ec256_public_t Enc_B_public_key;
    memset(&Enc_B_public_key, 0, sizeof(Enc_B_public_key));

    if(read(App_A_socket_fd, Enc_B_public_key.gx, SGX_ECP256_KEY_SIZE) < 0) {
        printf("[App A]: FAILED reception of the ECC public key (g^x) of Enclave B.\n");
        close(App_A_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App A]: SUCCESSFUL reception of the ECC public key (g^x) of Enclave B.\n");
    }
    if(read(App_A_socket_fd, Enc_B_public_key.gy, SGX_ECP256_KEY_SIZE) < 0) {
        printf("[App A]: FAILED reception of the ECC public key (g^y) of Enclave B.\n");
        close(App_A_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App A]: SUCCESSFUL reception of the ECC public key (g^y) of Enclave B.\n");
    }
    /*************************
    * END [1. App A receives the ECC public key of Enclave B from App B]
    *************************/

    /*************************
    * BEGIN [3. Enclave A calculates the shared Diffie-Hellman key]
    *************************/ 
    ret_status = compute_shared_dh_key(global_eid, &sgx_status, Enc_B_public_key);
    if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
      printf("[App A]: Enclave A FAILED to compute the shared DH key.\n");
      print_error_message(sgx_status);
      print_error_message(ret_status);
      close(App_A_socket_fd);
      sgx_destroy_enclave(global_eid);
      return -1;
    } else {
       printf("[App A]: Enclave A SUCCESSFULLY computed the shared DH key.\n");
    }
    /*************************
    * END [3. Enclave A calculates the shared Diffie-Hellman key]
    *************************/

    /*************************
    * BEGIN [0. Enclave A computes the encrypted PSK]
    *************************/
    uint8_t c;
    uint8_t ciphertext[DEFAULT_PSK_LENGTH];
    for(int i = 0; i < DEFAULT_PSK_LENGTH; i++) {
        ret_status = get_encrypted_PSK(global_eid, &sgx_status, &c, i);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            printf("[App A]: Enclave A FAILED to encrypt the PSK.\n");
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_A_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        }
        ciphertext[i] = c;
    }
    printf("[App A]: Enclave A SUCCESSFULLY encrypted the PSK.\n");
    /*************************
    * END [0. Enclave A computes the encrypted PSK]
    *************************/

    /*************************
    * BEGIN [1. App A sends the encrypted PSK of Enclave A to App B]
    *************************/ 
    if(write(App_A_socket_fd, &ciphertext, sizeof(ciphertext)) < (int) sizeof(ciphertext)) {
        printf("[App A]: FAILED transmission of the encrypted PSK of Enclave A.\n");
        close(App_A_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App A]: SUCCESSFUL transmission of the encrypted PSK of Enclave A.\n");
    }
    /*************************
    * END [1. App A sends the encrypted PSK of Enclave A to App B]
    *************************/

    /*************************
    * BEGIN [1. App A receives the encrypted PSK of Enclave B from App B]
    *************************/ 
    uint8_t Enc_B_encrypted_PSK[DEFAULT_PSK_LENGTH];
    if(read(App_A_socket_fd, &Enc_B_encrypted_PSK, sizeof(Enc_B_encrypted_PSK)) < 0) {
        printf("[App A]: FAILED reception of the encrypted PSK of Enclave B.\n");
        close(App_A_socket_fd);
        sgx_destroy_enclave(global_eid);
        return -1;
    } else {
        printf("[App A]: SUCCESSFUL reception of the encrypted PSK of Enclave B.\n");
    }
    /*************************
    * END [1. App A receives the encrypted PSK of Enclave B from App B]
    *************************/

    /*************************
    * BEGIN [0. Enclave A decrypts and verifies the encrypted PSK of Enclave B]
    *************************/
    int check = 0;
    for(int i = 0; i < DEFAULT_PSK_LENGTH; i++) {
        ret_status = decrypt_and_check_PSK(global_eid, &sgx_status, Enc_B_encrypted_PSK[i], i, &check);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_A_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        }
    }
    if(check == 0) {
        printf("[App A]: The decrypted PSK MATCHES the local PSK of Enclave B.\n");
    } else {
        printf("[App A]: The decrypted PSK DOES NOT MATCH the local PSK of Enclave B.\n");
    }
    /*************************
    * END [0. Enclave A decrypts and verifies the encrypted PSK of Enclave B]
    *************************/

    for(int i = 0; i < CHALLENGE_RESPONSE_ITERATION_NUM; i++) {
        printf("\n");
        printf("[App A]: ***** Challenge-Response N°%i *****\n", i+1);
        /*************************
        * BEGIN [4. Enclave A generates and encrypts the challenge]
        *************************/
        uint8_t encrypted_a = 0;
        uint8_t encrypted_separator = 0;
        uint8_t encrypted_b = 0;
        uint8_t challenge[3]; // challenge = AES-CTR('a' || ':' || 'b')
        ret_status = get_challenge(global_eid, &sgx_status, &encrypted_a, &encrypted_separator, &encrypted_b);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            printf("[App A]: Enclave A FAILED to generate and encrypt the challenge.\n");
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_A_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        } else {
            printf("[App A]: Enclave A SUCCESSFULLY generated and encrypted the challenge.\n");
        }
        challenge[0] = encrypted_a;
        challenge[1] = encrypted_separator;
        challenge[2] = encrypted_b;
        /*************************
        * END [4. Enclave A generates and encrypts the challenge]
        *************************/

        /*************************
        * BEGIN [1. App A sends the challenge to App B]
        *************************/ 
        if(write(App_A_socket_fd, &challenge, sizeof(challenge)) < (int) sizeof(challenge)) {
            printf("[App A]: FAILED transmission of the challenge.\n");
            close(App_A_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        } else {
            printf("[App A]: SUCCESSFUL transmission of the challenge.\n");
        }
        /*************************
        * END [1. App A sends the challenge to App B]
        *************************/

        /*************************
        * BEGIN [1. App A receives the encrypted response from App B]
        *************************/ 
        uint8_t encrypted_response;
        if(read(App_A_socket_fd, &encrypted_response, sizeof(encrypted_response)) < 0) {
            printf("[App A]: FAILED reception of the encrypted response.\n");
            close(App_A_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        } else {
            printf("[App A]: SUCCESSFUL reception of the encrypted response.\n");
        }
        /*************************
        * END [1. App A receives the encrypted response from App B]
        *************************/

        /*************************
        * BEGIN [5. Enclave A decrypts and verifies the response of Enclave B]
        *************************/ 
        int verify = 0;
        ret_status = decrypt_and_check_response(global_eid, &sgx_status, encrypted_response, &verify);
        if(sgx_status != SGX_SUCCESS || ret_status != SGX_SUCCESS) {
            print_error_message(sgx_status);
            print_error_message(ret_status);
            close(App_A_socket_fd);
            sgx_destroy_enclave(global_eid);
            return -1;
        }
        if(verify == 0) {
            printf("[App A]: The response MATCHES the sum of the random numbers a and b.\n");
        } else {
            printf("[App A]: The response DOES NOT MATCH the sum of the random numbers a and b.\n");
        }
        /*************************
        * END [5. Enclave A decrypts and verifies the response of Enclave B]
        *************************/
    }

    /* Terminates connection */
    close(App_A_socket_fd);
    /* Enclave A destruction */
    sgx_destroy_enclave(global_eid);

    printf("[App A]: Enclave A destroyed.\n");
    return 0;
}