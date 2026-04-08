There are two examples which load an EC key (secp256k1), saved in a file in PEM format, into the HSM, using hybrid encryption. Then sign something inside the HSM using the EC key, verify the signature inside the HSM, dump that signature into a file, and finally you can verify the signature outside the HSM, using OpenSSL.

rsa_aes_ec_import_sign: Uses hybrid encryption in one step, using CKM_RSA_AES_KEY_WRAP as mechanism in the unwrap function.
rsa_oaep_aes_gcm_ec_import_sign: Uses hybrid encryption in two steps. First unwrapping the ephemeral AES key using CKM_RSA_PKCS_OAEP mechanism, and then unwrapping the EC key using CKM_AES_GCM.

More details about those two examples mentioned above...

rsa_aes_ec_import_sign does this in one flow:
  - reads an EC private key in PEM format, converts the private key to PKCS#8 DER, and also extracts curve OID plus public point for later public-key object creation
  - generates an RSA wrap/unwrap keypair in the HSM
  - reproduces CKM_RSA_AES_KEY_WRAP client-side with OpenSSL: RSA-OAEP(SHA-256) over an ephemeral AES key, then AES key-wrap with padding over the PKCS#8 EC private key bytes. And concatenates both pieces into a CKM_RSA_AES_KEY_WRAP-compatible blob
  - unwraps the EC private key into the HSM
  - creates the matching EC public key object in the HSM
  - signs with CKM_ECDSA_SHA256, verifies inside the HSM, writes imported_ec_message.bin, imported_ec_signature.bin, and imported_ec_signature.der, and prints the OpenSSL verify commands

rsa_oaep_aes_gcm_ec_import_sign does the following:
  - client-side RSA-OAEP(SHA-256) wraps a temporary AES-256 key
  - client-side AES-GCM wraps the PKCS#8 EC private key DER
  - HSM C_UnwrapKey with CKM_RSA_PKCS_OAEP imports the temporary AES key
  - HSM C_UnwrapKey with CKM_AES_GCM imports the EC private key
  - then it creates the EC public key, signs, verifies, and writes the same output files as the original sample
Technical note:
  - CKM_AES_GCM unwrap expects ciphertext || tag in the wrapped blob, with IV passed via CK_GCM_PARAMS

How to use any of the examples mentioned above:

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
