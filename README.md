## Compilation

### /Enclave_A/App/

make clean
make SGX_MODE=SIM

### /Enclave_B/App/

make clean
make SGX_MODE=SIM

## Execution

Usage: ./app HOST_IP PORT

### /Enclave_A/App/

./app 127.0.0.1 4567

### /Enclave_B/App/

./app 127.0.0.1 4567

## Note

First execute the app binary in /Enclave_A/App/ and then in /Enclave_B/App/
