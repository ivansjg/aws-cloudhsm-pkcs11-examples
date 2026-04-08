The new binary rsa_aes_ec_import_sign does this in one flow:
  - reads ec_private_key.pem with OpenSSL and extracts the secp256k1 private scalar, curve OID, and public point
  - generates an RSA wrap/unwrap keypair in the HSM
  - reproduces CKM_RSA_AES_KEY_WRAP client-side with OpenSSL: RSA-OAEP(SHA-256) over an ephemeral AES key, then AES key-wrap with padding over the EC private scalar
  - unwraps the EC private key into the HSM
  - creates the matching EC public key object in the HSM
  - signs with CKM_ECDSA_SHA256, verifies inside the HSM, writes imported_ec_message.bin, imported_ec_signature.bin, and imported_ec_signature.der, and prints the OpenSSL verify commands

How to use it:

- Follow https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library.html to install AWS CloudHSM PKCS#11
- Configure it with the HSM:
```
sudo /opt/cloudhsm/bin/configure-pkcs11 -a CLOUDHSM_IP
```
- Generate secp256k1 key pair locally using OpenSSL:
```
openssl ecparam -name secp256k1 -genkey -noout -out ~/ec_private_key.pem
```
- Build source code: 
```
cd aws-cloudhsm-pkcs11-examples/
mkdir build
cd build/
cmake ..
make
```
- Run the code:
```
./src/wrapping/rsa_aes_ec_import_sign --pin fortris_app:fortris12345678 --library /opt/cloudhsm/lib/libcloudhsm_pkcs11.so --pem ~/ec_private_key.pem
```
