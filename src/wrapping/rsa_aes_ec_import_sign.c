/*
 * Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <common.h>

#define DEFAULT_EC_PEM_PATH "ec_private_key.pem"
#define DEFAULT_MESSAGE_FILE "imported_ec_message.bin"
#define DEFAULT_SIGNATURE_RAW_FILE "imported_ec_signature.bin"
#define DEFAULT_SIGNATURE_DER_FILE "imported_ec_signature.der"
#define DEFAULT_AES_KEY_BITS 256
#define MAX_SIGNATURE_LENGTH 256

struct imported_ec_material {
    CK_BYTE_PTR private_key_der;
    CK_ULONG private_key_der_len;
    CK_BYTE_PTR ec_params;
    CK_ULONG ec_params_len;
    CK_BYTE_PTR raw_ec_point;
    CK_ULONG raw_ec_point_len;
    CK_BYTE_PTR ec_point;
    CK_ULONG ec_point_len;
};

static void free_imported_ec_material(struct imported_ec_material *material) {
    if (material == NULL) {
        return;
    }

    free(material->private_key_der);
    free(material->ec_params);
    free(material->raw_ec_point);
    free(material->ec_point);

    memset(material, 0, sizeof(*material));
}

static void destroy_object_if_valid(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object_handle) {
    if (object_handle == CK_INVALID_HANDLE) {
        return;
    }

    CK_RV rv = funcs->C_DestroyObject(session, object_handle);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to destroy object %lu: %lu\n", object_handle, rv);
    }
}

static const char *get_optional_argument(int argc, char **argv, const char *name) {
    int i = 0;

    if (name == NULL || argv == NULL) {
        return NULL;
    }

    for (i = 1; i < argc - 1; i++) {
        if (argv[i] != NULL && strcmp(argv[i], name) == 0) {
            return argv[i + 1];
        }
    }

    return NULL;
}

static CK_RV write_binary_file(const char *path, const CK_BYTE_PTR data, CK_ULONG data_len) {
    FILE *fp = NULL;

    if (path == NULL || data == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s for writing\n", path);
        return CKR_FUNCTION_FAILED;
    }

    if (data_len > 0 && fwrite(data, 1, data_len, fp) != data_len) {
        fprintf(stderr, "Failed to write %s\n", path);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    if (fclose(fp) != 0) {
        fprintf(stderr, "Failed to close %s\n", path);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV encode_asn1_octet_string(
        const unsigned char *input,
        size_t input_len,
        CK_BYTE_PTR *encoded_output,
        CK_ULONG *encoded_output_len) {
    ASN1_OCTET_STRING *octet_string = NULL;
    unsigned char *cursor = NULL;
    int der_len = 0;

    if (input == NULL || encoded_output == NULL || encoded_output_len == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    octet_string = ASN1_OCTET_STRING_new();
    if (octet_string == NULL) {
        return CKR_HOST_MEMORY;
    }

    if (ASN1_OCTET_STRING_set(octet_string, input, (int) input_len) != 1) {
        ASN1_OCTET_STRING_free(octet_string);
        return CKR_FUNCTION_FAILED;
    }

    der_len = i2d_ASN1_OCTET_STRING(octet_string, NULL);
    if (der_len <= 0) {
        ASN1_OCTET_STRING_free(octet_string);
        return CKR_FUNCTION_FAILED;
    }

    *encoded_output = malloc((size_t) der_len);
    if (*encoded_output == NULL) {
        ASN1_OCTET_STRING_free(octet_string);
        return CKR_HOST_MEMORY;
    }

    cursor = *encoded_output;
    der_len = i2d_ASN1_OCTET_STRING(octet_string, &cursor);
    ASN1_OCTET_STRING_free(octet_string);
    if (der_len <= 0) {
        free(*encoded_output);
        *encoded_output = NULL;
        return CKR_FUNCTION_FAILED;
    }

    *encoded_output_len = (CK_ULONG) der_len;
    return CKR_OK;
}

static CK_RV load_ec_material_from_pem(
        const char *pem_path,
        struct imported_ec_material *material) {
    CK_RV rv = CKR_FUNCTION_FAILED;
    FILE *pem_file = NULL;
    EVP_PKEY *private_key = NULL;
    PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
    EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *public_point = NULL;
    ASN1_OBJECT *curve_oid = NULL;
    unsigned char *private_der_cursor = NULL;
    unsigned char *oid_cursor = NULL;
    unsigned char *point_bytes = NULL;
    size_t point_len = 0;
    int curve_nid = 0;
    int der_len = 0;

    if (pem_path == NULL || material == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    pem_file = fopen(pem_path, "r");
    if (pem_file == NULL) {
        fprintf(stderr, "Failed to open EC PEM file: %s\n", pem_path);
        return CKR_FUNCTION_FAILED;
    }

    private_key = PEM_read_PrivateKey(pem_file, NULL, NULL, NULL);
    fclose(pem_file);
    pem_file = NULL;
    if (private_key == NULL) {
        fprintf(stderr, "Failed to parse EC private key: %s\n", pem_path);
        return CKR_FUNCTION_FAILED;
    }

    ec_key = EVP_PKEY_get1_EC_KEY(private_key);
    if (ec_key == NULL) {
        fprintf(stderr, "PEM does not contain an EC private key\n");
        goto done;
    }

    group = EC_KEY_get0_group(ec_key);
    public_point = EC_KEY_get0_public_key(ec_key);
    if (group == NULL || public_point == NULL) {
        fprintf(stderr, "PEM is missing required EC key components\n");
        goto done;
    }

    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid == NID_undef) {
        fprintf(stderr, "EC key does not use a named curve\n");
        goto done;
    }

    curve_oid = OBJ_nid2obj(curve_nid);
    if (curve_oid == NULL) {
        fprintf(stderr, "Failed to map curve NID to OID\n");
        goto done;
    }

    der_len = i2d_ASN1_OBJECT(curve_oid, NULL);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to encode EC params OID\n");
        goto done;
    }

    material->ec_params = malloc((size_t) der_len);
    if (material->ec_params == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    oid_cursor = material->ec_params;
    der_len = i2d_ASN1_OBJECT(curve_oid, &oid_cursor);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to serialize EC params OID\n");
        goto done;
    }
    material->ec_params_len = (CK_ULONG) der_len;

    pkcs8 = EVP_PKEY2PKCS8(private_key);
    if (pkcs8 == NULL) {
        fprintf(stderr, "Failed to convert EC private key to PKCS#8\n");
        goto done;
    }

    der_len = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, NULL);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to determine PKCS#8 length\n");
        goto done;
    }

    material->private_key_der = malloc((size_t) der_len);
    if (material->private_key_der == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    private_der_cursor = material->private_key_der;
    der_len = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &private_der_cursor);
    if (der_len <= 0) {
        fprintf(stderr, "Failed to serialize PKCS#8 EC private key\n");
        goto done;
    }
    material->private_key_der_len = (CK_ULONG) der_len;

    point_len = EC_POINT_point2oct(group,
                                   public_point,
                                   POINT_CONVERSION_UNCOMPRESSED,
                                   NULL,
                                   0,
                                   NULL);
    if (point_len == 0) {
        fprintf(stderr, "Failed to determine EC public point length\n");
        goto done;
    }

    point_bytes = malloc(point_len);
    if (point_bytes == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    if (EC_POINT_point2oct(group,
                           public_point,
                           POINT_CONVERSION_UNCOMPRESSED,
                           point_bytes,
                           point_len,
                           NULL) != point_len) {
        fprintf(stderr, "Failed to serialize EC public point\n");
        goto done;
    }

    material->raw_ec_point = point_bytes;
    material->raw_ec_point_len = (CK_ULONG) point_len;
    point_bytes = NULL;

    rv = encode_asn1_octet_string(material->raw_ec_point,
                                  material->raw_ec_point_len,
                                  &material->ec_point,
                                  &material->ec_point_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to encode EC point for PKCS#11 import: %lu\n", rv);
    }

done:
    free(point_bytes);
    PKCS8_PRIV_KEY_INFO_free(pkcs8);
    EVP_PKEY_free(private_key);
    EC_KEY_free(ec_key);
    if (rv != CKR_OK) {
        free_imported_ec_material(material);
    }
    return rv;
}

static CK_RV generate_wrapping_keypair(
        CK_SESSION_HANDLE session,
        CK_ULONG key_length_bits,
        CK_OBJECT_HANDLE_PTR public_key,
        CK_OBJECT_HANDLE_PTR private_key) {
    CK_MECHANISM mech = {CKM_RSA_X9_31_KEY_PAIR_GEN, NULL, 0};
    CK_BYTE public_exponent[] = {0x01, 0x00, 0x01};

    CK_ATTRIBUTE public_key_template[] = {
            {CKA_TOKEN,           &true_val,          sizeof(CK_BBOOL)},
            {CKA_WRAP,            &true_val,          sizeof(CK_BBOOL)},
            {CKA_MODULUS_BITS,    &key_length_bits,   sizeof(CK_ULONG)},
            {CKA_PUBLIC_EXPONENT, public_exponent,    sizeof(public_exponent)},
    };

    CK_ATTRIBUTE private_key_template[] = {
            {CKA_TOKEN,  &true_val, sizeof(CK_BBOOL)},
            {CKA_UNWRAP, &true_val, sizeof(CK_BBOOL)},
    };

    return funcs->C_GenerateKeyPair(session,
                                    &mech,
                                    public_key_template,
                                    sizeof(public_key_template) / sizeof(CK_ATTRIBUTE),
                                    private_key_template,
                                    sizeof(private_key_template) / sizeof(CK_ATTRIBUTE),
                                    public_key,
                                    private_key);
}

static CK_RV build_rsa_public_key_from_hsm(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE public_key_handle,
        EVP_PKEY **public_key) {
    CK_RV rv = CKR_FUNCTION_FAILED;
    CK_ATTRIBUTE attrs[] = {
            {CKA_MODULUS, NULL, 0},
            {CKA_PUBLIC_EXPONENT, NULL, 0},
    };
    BIGNUM *modulus = NULL;
    BIGNUM *public_exponent = NULL;
    RSA *rsa = NULL;
    EVP_PKEY *evp_public_key = NULL;

    if (public_key == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    rv = funcs->C_GetAttributeValue(session, public_key_handle, attrs, sizeof(attrs) / sizeof(CK_ATTRIBUTE));
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to query RSA public key attributes: %lu\n", rv);
        return rv;
    }

    attrs[0].pValue = malloc(attrs[0].ulValueLen);
    attrs[1].pValue = malloc(attrs[1].ulValueLen);
    if (attrs[0].pValue == NULL || attrs[1].pValue == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    rv = funcs->C_GetAttributeValue(session, public_key_handle, attrs, sizeof(attrs) / sizeof(CK_ATTRIBUTE));
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to read RSA public key attributes: %lu\n", rv);
        goto done;
    }

    modulus = BN_bin2bn(attrs[0].pValue, (int) attrs[0].ulValueLen, NULL);
    public_exponent = BN_bin2bn(attrs[1].pValue, (int) attrs[1].ulValueLen, NULL);
    if (modulus == NULL || public_exponent == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    rsa = RSA_new();
    if (rsa == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (RSA_set0_key(rsa, modulus, public_exponent, NULL) != 1) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }
    modulus = NULL;
    public_exponent = NULL;

    evp_public_key = EVP_PKEY_new();
    if (evp_public_key == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_assign_RSA(evp_public_key, rsa) != 1) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }
    rsa = NULL;

    *public_key = evp_public_key;
    evp_public_key = NULL;
    rv = CKR_OK;

done:
    free(attrs[0].pValue);
    free(attrs[1].pValue);
    BN_free(modulus);
    BN_free(public_exponent);
    RSA_free(rsa);
    EVP_PKEY_free(evp_public_key);
    return rv;
}

static CK_RV aes_wrap_with_padding(
        const unsigned char *wrapping_key,
        size_t wrapping_key_len,
        const CK_BYTE_PTR plaintext,
        CK_ULONG plaintext_len,
        CK_BYTE_PTR *wrapped_output,
        CK_ULONG *wrapped_output_len) {
    CK_RV rv = CKR_FUNCTION_FAILED;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *ciphertext = NULL;
    int update_len = 0;
    int final_len = 0;
    int total_len = 0;
    const EVP_CIPHER *cipher = NULL;

    if (wrapping_key == NULL || plaintext == NULL || wrapped_output == NULL || wrapped_output_len == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    switch (wrapping_key_len) {
        case 16:
            cipher = EVP_aes_128_wrap_pad();
            break;
        case 24:
            cipher = EVP_aes_192_wrap_pad();
            break;
        case 32:
            cipher = EVP_aes_256_wrap_pad();
            break;
        default:
            fprintf(stderr, "Unsupported AES key length for key wrap: %zu bytes\n", wrapping_key_len);
            return CKR_KEY_SIZE_RANGE;
    }

    ciphertext = malloc((size_t) plaintext_len + 16);
    if (ciphertext == NULL) {
        return CKR_HOST_MEMORY;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, wrapping_key, NULL) != 1) {
        goto done;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &update_len, plaintext, (int) plaintext_len) != 1) {
        goto done;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + update_len, &final_len) != 1) {
        goto done;
    }

    total_len = update_len + final_len;
    *wrapped_output = ciphertext;
    *wrapped_output_len = (CK_ULONG) total_len;
    ciphertext = NULL;
    rv = CKR_OK;

done:
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);
    return rv;
}

static CK_RV rsa_oaep_wrap_buffer(
        EVP_PKEY *public_key,
        const unsigned char *plaintext,
        size_t plaintext_len,
        CK_BYTE_PTR *wrapped_output,
        CK_ULONG *wrapped_output_len) {
    CK_RV rv = CKR_FUNCTION_FAILED;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;

    if (public_key == NULL || plaintext == NULL || wrapped_output == NULL || wrapped_output_len == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (ctx == NULL) {
        return CKR_HOST_MEMORY;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        goto done;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &ciphertext_len, plaintext, plaintext_len) <= 0) {
        goto done;
    }

    ciphertext = malloc(ciphertext_len);
    if (ciphertext == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) <= 0) {
        goto done;
    }

    *wrapped_output = ciphertext;
    *wrapped_output_len = (CK_ULONG) ciphertext_len;
    ciphertext = NULL;
    rv = CKR_OK;

done:
    free(ciphertext);
    EVP_PKEY_CTX_free(ctx);
    return rv;
}

static CK_RV build_rsa_aes_wrapped_blob(
        EVP_PKEY *rsa_public_key,
        CK_ULONG aes_key_bits,
        const CK_BYTE_PTR key_bytes,
        CK_ULONG key_bytes_len,
        CK_BYTE_PTR *wrapped_output,
        CK_ULONG *wrapped_output_len) {
    CK_RV rv = CKR_FUNCTION_FAILED;
    CK_BYTE_PTR rsa_wrapped_aes_key = NULL;
    CK_BYTE_PTR aes_wrapped_key = NULL;
    CK_BYTE_PTR combined_wrapped_key = NULL;
    CK_ULONG rsa_wrapped_aes_key_len = 0;
    CK_ULONG aes_wrapped_key_len = 0;
    unsigned char aes_key[32];
    size_t aes_key_len = aes_key_bits / 8;

    if (aes_key_len > sizeof(aes_key) || wrapped_output == NULL || wrapped_output_len == NULL) {
        return CKR_ARGUMENTS_BAD;
    }

    if (RAND_bytes(aes_key, (int) aes_key_len) != 1) {
        return CKR_FUNCTION_FAILED;
    }

    rv = rsa_oaep_wrap_buffer(rsa_public_key, aes_key, aes_key_len, &rsa_wrapped_aes_key, &rsa_wrapped_aes_key_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "RSA OAEP wrapping of the ephemeral AES key failed: %lu\n", rv);
        goto done;
    }

    rv = aes_wrap_with_padding(aes_key, aes_key_len, key_bytes, key_bytes_len, &aes_wrapped_key, &aes_wrapped_key_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "AES key wrap of the EC private value failed: %lu\n", rv);
        goto done;
    }

    combined_wrapped_key = malloc((size_t) rsa_wrapped_aes_key_len + aes_wrapped_key_len);
    if (combined_wrapped_key == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    memcpy(combined_wrapped_key, rsa_wrapped_aes_key, rsa_wrapped_aes_key_len);
    memcpy(combined_wrapped_key + rsa_wrapped_aes_key_len, aes_wrapped_key, aes_wrapped_key_len);

    *wrapped_output = combined_wrapped_key;
    *wrapped_output_len = rsa_wrapped_aes_key_len + aes_wrapped_key_len;
    combined_wrapped_key = NULL;
    rv = CKR_OK;

done:
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    free(rsa_wrapped_aes_key);
    free(aes_wrapped_key);
    free(combined_wrapped_key);
    return rv;
}

static CK_RV import_ec_public_key(
        CK_SESSION_HANDLE session,
        const struct imported_ec_material *material,
        CK_OBJECT_HANDLE_PTR public_key_handle) {
    CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_BYTE key_id[] = "imported-secp256k1";
    CK_BYTE label[] = "imported-secp256k1-public";
    CK_RV rv = CKR_FUNCTION_FAILED;

    CK_ATTRIBUTE public_template_der[] = {
            {CKA_CLASS,     &key_class,               sizeof(key_class)},
            {CKA_KEY_TYPE,  &key_type,                sizeof(key_type)},
            {CKA_TOKEN,     &false_val,               sizeof(CK_BBOOL)},
            {CKA_VERIFY,    &true_val,                sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS, material->ec_params,      material->ec_params_len},
            {CKA_EC_POINT,  material->ec_point,       material->ec_point_len},
            {CKA_ID,        key_id,                   sizeof(key_id) - 1},
            {CKA_LABEL,     label,                    sizeof(label) - 1},
    };

    CK_ATTRIBUTE public_template_raw[] = {
            {CKA_CLASS,     &key_class,               sizeof(key_class)},
            {CKA_KEY_TYPE,  &key_type,                sizeof(key_type)},
            {CKA_TOKEN,     &false_val,               sizeof(CK_BBOOL)},
            {CKA_VERIFY,    &true_val,                sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS, material->ec_params,      material->ec_params_len},
            {CKA_EC_POINT,  material->raw_ec_point,   material->raw_ec_point_len},
            {CKA_ID,        key_id,                   sizeof(key_id) - 1},
            {CKA_LABEL,     label,                    sizeof(label) - 1},
    };

    rv = funcs->C_CreateObject(session,
                               public_template_raw,
                               sizeof(public_template_raw) / sizeof(CK_ATTRIBUTE),
                               public_key_handle);
    if (rv == CKR_OK) {
        return rv;
    }

    if (rv != CKR_ATTRIBUTE_VALUE_INVALID && rv != CKR_TEMPLATE_INCONSISTENT) {
        return rv;
    }

    rv = funcs->C_CreateObject(session,
                               public_template_der,
                               sizeof(public_template_der) / sizeof(CK_ATTRIBUTE),
                               public_key_handle);
    return rv;
}

static CK_RV unwrap_ec_private_key(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE unwrapping_key,
        const struct imported_ec_material *material,
        CK_BYTE_PTR wrapped_key,
        CK_ULONG wrapped_key_len,
        CK_OBJECT_HANDLE_PTR private_key_handle) {
    CK_ULONG aes_key_bits = DEFAULT_AES_KEY_BITS;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params = {CKM_SHA256, CKG_MGF1_SHA256};
    CK_RSA_AES_KEY_WRAP_PARAMS params = {aes_key_bits, &oaep_params};
    CK_MECHANISM mech = {CKM_RSA_AES_KEY_WRAP, &params, sizeof(params)};
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_BBOOL true_boolean = TRUE;
    CK_BYTE key_id[] = "imported-secp256k1";
    CK_BYTE label[] = "imported-secp256k1-private";

    CK_ATTRIBUTE private_template[] = {
            {CKA_CLASS,       &key_class,               sizeof(key_class)},
            {CKA_KEY_TYPE,    &key_type,                sizeof(key_type)},
            {CKA_TOKEN,       &false_val,               sizeof(CK_BBOOL)},
            {CKA_PRIVATE,     &true_boolean,            sizeof(CK_BBOOL)},
            {CKA_SENSITIVE,   &true_boolean,            sizeof(CK_BBOOL)},
            {CKA_EXTRACTABLE, &false_val,               sizeof(CK_BBOOL)},
            {CKA_SIGN,        &true_val,                sizeof(CK_BBOOL)},
            {CKA_ID,          key_id,                   sizeof(key_id) - 1},
            {CKA_LABEL,       label,                    sizeof(label) - 1},
    };

    return funcs->C_UnwrapKey(session,
                              &mech,
                              unwrapping_key,
                              wrapped_key,
                              wrapped_key_len,
                              private_template,
                              sizeof(private_template) / sizeof(CK_ATTRIBUTE),
                              private_key_handle);
}

static CK_RV sign_with_hsm(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE private_key_handle,
        CK_MECHANISM_TYPE mechanism_type,
        CK_BYTE_PTR data,
        CK_ULONG data_len,
        CK_BYTE_PTR signature,
        CK_ULONG_PTR signature_len) {
    CK_MECHANISM mechanism = {mechanism_type, NULL, 0};
    CK_RV rv = funcs->C_SignInit(session, &mechanism, private_key_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    return funcs->C_Sign(session, data, data_len, signature, signature_len);
}

static CK_RV verify_with_hsm(
        CK_SESSION_HANDLE session,
        CK_OBJECT_HANDLE public_key_handle,
        CK_MECHANISM_TYPE mechanism_type,
        CK_BYTE_PTR data,
        CK_ULONG data_len,
        CK_BYTE_PTR signature,
        CK_ULONG signature_len) {
    CK_MECHANISM mechanism = {mechanism_type, NULL, 0};
    CK_RV rv = funcs->C_VerifyInit(session, &mechanism, public_key_handle);
    if (rv != CKR_OK) {
        return rv;
    }

    return funcs->C_Verify(session, data, data_len, signature, signature_len);
}

static CK_RV ecdsa_raw_signature_to_der(
        CK_BYTE_PTR raw_signature,
        CK_ULONG raw_signature_len,
        CK_BYTE_PTR *der_signature,
        CK_ULONG *der_signature_len) {
    CK_RV rv = CKR_FUNCTION_FAILED;
    BIGNUM *r = NULL;
    BIGNUM *s = NULL;
    ECDSA_SIG *ecdsa_sig = NULL;
    unsigned char *cursor = NULL;
    int der_len = 0;
    CK_ULONG component_len = raw_signature_len / 2;

    if (raw_signature == NULL || der_signature == NULL || der_signature_len == NULL || raw_signature_len == 0) {
        return CKR_ARGUMENTS_BAD;
    }

    if ((raw_signature_len % 2) != 0) {
        fprintf(stderr, "Unexpected raw ECDSA signature length: %lu\n", raw_signature_len);
        return CKR_SIGNATURE_INVALID;
    }

    r = BN_bin2bn(raw_signature, (int) component_len, NULL);
    s = BN_bin2bn(raw_signature + component_len, (int) component_len, NULL);
    if (r == NULL || s == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    ecdsa_sig = ECDSA_SIG_new();
    if (ecdsa_sig == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    if (ECDSA_SIG_set0(ecdsa_sig, r, s) != 1) {
        goto done;
    }
    r = NULL;
    s = NULL;

    der_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
    if (der_len <= 0) {
        goto done;
    }

    *der_signature = malloc((size_t) der_len);
    if (*der_signature == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    cursor = *der_signature;
    der_len = i2d_ECDSA_SIG(ecdsa_sig, &cursor);
    if (der_len <= 0) {
        free(*der_signature);
        *der_signature = NULL;
        goto done;
    }

    *der_signature_len = (CK_ULONG) der_len;
    rv = CKR_OK;

done:
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(ecdsa_sig);
    return rv;
}

int main(int argc, char **argv) {
    static CK_BYTE sign_data[] = "Message signed with imported secp256k1 key";
    const char *pem_path = get_optional_argument(argc, argv, "--pem");
    CK_RV rv = CKR_FUNCTION_FAILED;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_private_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE imported_public_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE imported_private_key = CK_INVALID_HANDLE;
    CK_BYTE_PTR wrapped_private_key = NULL;
    CK_ULONG wrapped_private_key_len = 0;
    CK_BYTE signature[MAX_SIGNATURE_LENGTH];
    CK_ULONG signature_len = sizeof(signature);
    CK_BYTE_PTR der_signature = NULL;
    CK_ULONG der_signature_len = 0;
    EVP_PKEY *rsa_wrapping_public_key = NULL;
    struct imported_ec_material material = {0};
    struct pkcs_arguments args = {0};

    if (get_pkcs_args(argc, argv, &args) < 0) {
        return EXIT_FAILURE;
    }

    if (pem_path == NULL) {
        pem_path = DEFAULT_EC_PEM_PATH;
    }

    rv = pkcs11_initialize(args.library);
    if (rv != CKR_OK) {
        return EXIT_FAILURE;
    }

    rv = pkcs11_open_session(args.pin, &session);
    if (rv != CKR_OK) {
        return EXIT_FAILURE;
    }

    rv = load_ec_material_from_pem(pem_path, &material);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = generate_wrapping_keypair(session, 2048, &rsa_public_key, &rsa_private_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to generate RSA wrapping keypair: %lu\n", rv);
        goto done;
    }
    printf("Generated RSA wrapping keypair. Public handle: %lu, Private handle: %lu\n",
           rsa_public_key,
           rsa_private_key);

    rv = build_rsa_public_key_from_hsm(session, rsa_public_key, &rsa_wrapping_public_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to export RSA public key from HSM: %lu\n", rv);
        goto done;
    }

    rv = build_rsa_aes_wrapped_blob(rsa_wrapping_public_key,
                                    DEFAULT_AES_KEY_BITS,
                                    material.private_key_der,
                                    material.private_key_der_len,
                                    &wrapped_private_key,
                                    &wrapped_private_key_len);
    if (rv != CKR_OK) {
        goto done;
    }
    printf("Wrapped PKCS#8 EC private key with CKM_RSA_AES_KEY_WRAP-compatible format (%lu bytes)\n",
           wrapped_private_key_len);

    rv = unwrap_ec_private_key(session,
                               rsa_private_key,
                               &material,
                               wrapped_private_key,
                               wrapped_private_key_len,
                               &imported_private_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to unwrap EC private key into the HSM: %lu\n", rv);
        goto done;
    }
    printf("Imported EC private key handle: %lu\n", imported_private_key);

    rv = import_ec_public_key(session, &material, &imported_public_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to create EC public key object in the HSM: %lu\n", rv);
        goto done;
    }
    printf("Created matching EC public key handle: %lu\n", imported_public_key);

    rv = sign_with_hsm(session,
                       imported_private_key,
                       CKM_ECDSA_SHA256,
                       sign_data,
                       (CK_ULONG) strlen((char *) sign_data),
                       signature,
                       &signature_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to sign with imported EC private key: %lu\n", rv);
        goto done;
    }

    printf("HSM signature (%lu bytes, raw r||s): ", signature_len);
    if (print_bytes_as_hex((char *) signature, signature_len) != 0) {
        fprintf(stderr, "Failed to print signature\n");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    rv = verify_with_hsm(session,
                         imported_public_key,
                         CKM_ECDSA_SHA256,
                         sign_data,
                         (CK_ULONG) strlen((char *) sign_data),
                         signature,
                         signature_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "HSM verification failed: %lu\n", rv);
        goto done;
    }
    printf("HSM verification succeeded\n");

    rv = ecdsa_raw_signature_to_der(signature, signature_len, &der_signature, &der_signature_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to convert signature to DER: %lu\n", rv);
        goto done;
    }

    rv = write_binary_file(DEFAULT_MESSAGE_FILE, sign_data, (CK_ULONG) strlen((char *) sign_data));
    if (rv != CKR_OK) {
        goto done;
    }

    rv = write_binary_file(DEFAULT_SIGNATURE_RAW_FILE, signature, signature_len);
    if (rv != CKR_OK) {
        goto done;
    }

    rv = write_binary_file(DEFAULT_SIGNATURE_DER_FILE, der_signature, der_signature_len);
    if (rv != CKR_OK) {
        goto done;
    }

    printf("Wrote %s, %s, and %s\n",
           DEFAULT_MESSAGE_FILE,
           DEFAULT_SIGNATURE_RAW_FILE,
           DEFAULT_SIGNATURE_DER_FILE);
    printf("Verify outside the HSM with OpenSSL:\n");
    printf("  openssl pkey -in %s -pubout -out imported_ec_public.pem\n", pem_path);
    printf("  openssl dgst -sha256 -verify imported_ec_public.pem -signature %s %s\n",
           DEFAULT_SIGNATURE_DER_FILE,
           DEFAULT_MESSAGE_FILE);

    rv = CKR_OK;

done:
    free(wrapped_private_key);
    free(der_signature);
    EVP_PKEY_free(rsa_wrapping_public_key);
    free_imported_ec_material(&material);
    destroy_object_if_valid(session, imported_public_key);
    destroy_object_if_valid(session, imported_private_key);
    destroy_object_if_valid(session, rsa_public_key);
    destroy_object_if_valid(session, rsa_private_key);
    if (session != CK_INVALID_HANDLE) {
        pkcs11_finalize_session(session);
    }

    return rv == CKR_OK ? EXIT_SUCCESS : EXIT_FAILURE;
}
