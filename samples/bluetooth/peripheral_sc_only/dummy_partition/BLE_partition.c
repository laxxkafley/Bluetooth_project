// /*
//  * Copyright (c) 2021 Nordic Semiconductor ASA
//  *
//  * SPDX-License-Identifier: Apache-2.0
//  */

// #include <psa/crypto.h>
// #include <stdbool.h>
// #include <stdint.h>

// #include "psa/service.h"
// #include "psa_manifest/tfm_dummy_partition.h"

// #define NUM_SECRETS 5

// struct dp_secret {
// 	uint8_t secret[16];
// };

// struct dp_secret secrets[NUM_SECRETS] = {
// 	{ {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// };

// typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
// 				     uint32_t digest_size);

// static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
// 			size_t digest_size, size_t *p_digest_size,
// 			psa_write_callback_t callback, void *handle)
// {
// 	uint8_t digest[32];
// 	psa_status_t status;

// 	/* Check that secret_index is valid. */
// 	if (secret_index >= NUM_SECRETS) {
// 		return PSA_ERROR_INVALID_ARGUMENT;
// 	}

// 	/* Check that digest_size is valid. */
// 	if (digest_size != sizeof(digest)) {
// 		return PSA_ERROR_INVALID_ARGUMENT;
// 	}

// 	status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
// 				sizeof(secrets[secret_index].secret), digest,
// 				digest_size, p_digest_size);

// 	if (status != PSA_SUCCESS) {
// 		return status;
// 	}
// 	if (*p_digest_size != digest_size) {
// 		return PSA_ERROR_PROGRAMMER_ERROR;
// 	}

// 	callback(handle, digest, digest_size);

// 	return PSA_SUCCESS;
// }

// typedef psa_status_t (*dp_func_t)(psa_msg_t *);

// static void psa_write_digest(void *handle, uint8_t *digest,
// 			     uint32_t digest_size)
// {
// 	psa_write((psa_handle_t)handle, 0, digest, digest_size);
// }

// static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
// {
// 	size_t num = 0;
// 	uint32_t secret_index;

// 	if (msg->in_size[0] != sizeof(secret_index)) {
// 		/* The size of the argument is incorrect */
// 		return PSA_ERROR_PROGRAMMER_ERROR;
// 	}

// 	num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
// 	if (num != msg->in_size[0]) {
// 		return PSA_ERROR_PROGRAMMER_ERROR;
// 	}

// 	return tfm_dp_secret_digest(secret_index, msg->out_size[0],
// 				    &msg->out_size[0], psa_write_digest,
// 				    (void *)msg->handle);
// }

// static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
// {
// 	psa_status_t status;
// 	psa_msg_t msg;

// 	status = psa_get(signal, &msg);
// 	switch (msg.type) {
// 	case PSA_IPC_CONNECT:
// 		psa_reply(msg.handle, PSA_SUCCESS);
// 		break;
// 	case PSA_IPC_CALL:
// 		status = pfn(&msg);
// 		psa_reply(msg.handle, status);
// 		break;
// 	case PSA_IPC_DISCONNECT:
// 		psa_reply(msg.handle, PSA_SUCCESS);
// 		break;
// 	default:
// 		psa_panic();
// 	}
// }

// psa_status_t tfm_dp_req_mngr_init(void)
// {
// 	psa_signal_t signals = 0;

// 	while (1) {
// 		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
// 		if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
// 			dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// 					 tfm_dp_secret_digest_ipc);
// 		} else {
// 			psa_panic();
// 		}
// 	}

// 	return PSA_ERROR_SERVICE_FAILURE;
// }




// #include <psa/crypto.h>
// #include <stdbool.h>
// #include <stdint.h>
// #include <stdio.h>

// #include "psa/service.h"
// #include "psa_manifest/tfm_dummy_partition.h" //dummy

// #define NUM_SECRETS 5

// struct dp_secret {
// 	uint8_t secret[16];
// };

// struct dp_secret secrets[NUM_SECRETS] = {
// 	{ {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// 	{ {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// };

// typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
// 				     uint32_t digest_size);

// /* -------------------- Secret Digest Service -------------------- */
// static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
// 			size_t digest_size, size_t *p_digest_size,
// 			psa_write_callback_t callback, void *handle)
// {
// 	uint8_t digest[32];
// 	psa_status_t status;

// 	if (secret_index >= NUM_SECRETS) {
// 		return PSA_ERROR_INVALID_ARGUMENT;
// 	}

// 	if (digest_size != sizeof(digest)) {
// 		return PSA_ERROR_INVALID_ARGUMENT;
// 	}

// 	status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
// 				sizeof(secrets[secret_index].secret), digest,
// 				digest_size, p_digest_size);

// 	if (status != PSA_SUCCESS) {
// 		return status;
// 	}
// 	if (*p_digest_size != digest_size) {
// 		return PSA_ERROR_PROGRAMMER_ERROR;
// 	}

// 	callback(handle, digest, digest_size);

// 	return PSA_SUCCESS;
// }

// static void psa_write_digest(void *handle, uint8_t *digest,
// 			     uint32_t digest_size)
// {
// 	psa_write((psa_handle_t)handle, 0, digest, digest_size);
// }

// static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
// {
// 	size_t num = 0;
// 	uint32_t secret_index;

// 	if (msg->in_size[0] != sizeof(secret_index)) {
// 		return PSA_ERROR_PROGRAMMER_ERROR;
// 	}

// 	num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
// 	if (num != msg->in_size[0]) {
// 		return PSA_ERROR_PROGRAMMER_ERROR;
// 	}

// 	return tfm_dp_secret_digest(secret_index, msg->out_size[0],
// 				    &msg->out_size[0], psa_write_digest,
// 				    (void *)msg->handle);
// }

// /* -------------------- Jasmine Service -------------------- */
// static psa_status_t tfm_jas_hi_service_ipc(psa_msg_t *msg)
// {
// 	const char hi_msg[] = "Hi, I'm Jasmine, I like pizzaaaaaaaaaa and sleep";

// 	if (msg->out_size[0] < sizeof(hi_msg)) {
// 		return PSA_ERROR_PROGRAMMER_ERROR;
// 	}

// 	psa_write(msg->handle, 0, hi_msg, sizeof(hi_msg));

// 	return PSA_SUCCESS;
// }

// /* -------------------- Dispatcher -------------------- */
// typedef psa_status_t (*dp_func_t)(psa_msg_t *msg);

// static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
// {
// 	psa_status_t status;
// 	psa_msg_t msg;

// 	status = psa_get(signal, &msg);
// 	switch (msg.type) {
// 	case PSA_IPC_CONNECT:
// 		psa_reply(msg.handle, PSA_SUCCESS);
// 		break;
// 	case PSA_IPC_CALL:
// 		status = pfn(&msg);
// 		psa_reply(msg.handle, status);
// 		break;
// 	case PSA_IPC_DISCONNECT:
// 		psa_reply(msg.handle, PSA_SUCCESS);
// 		break;
// 	default:
// 		psa_panic();
// 	}
// }

// psa_status_t tfm_dp_req_mngr_init(void)
// {
// 	psa_signal_t signals = 0;

// 	while (1) {
// 		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

// 		if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
// 			dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// 					 tfm_dp_secret_digest_ipc);
// 		} else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
// 			dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
// 					 tfm_jas_hi_service_ipc);
// 		} else {
// 			psa_panic();
// 		}
// 	}

// 	return PSA_ERROR_SERVICE_FAILURE;
// }



















// #include <psa/crypto.h>                     // PSA Crypto API for hashing and cryptographic operations
                      
// #include <stdio.h>                          // Standard I/O (not heavily used here but included)
// #include "psa/service.h"                    // PSA service API for secure partition communication
// #include "psa_manifest/tfm_dummy_partition.h" // Manifest header for this dummy partition (service IDs, signals)

// #define NUM_SECRETS 5                       // Total number of stored secrets
// #define TFN_PUBKEY_EXPORT_LEN 65 //keygeneration

// #define TFN_ECDH_SHARED_KEY_LEN 32  // 256-bit shared secret


// static psa_key_id_t sec_ble_key_id = 0;  // 0 = invalid key




// static psa_status_t tfm_ble_keygen_service_ipc(psa_msg_t *msg)
// {
//     psa_status_t status;
//     psa_key_id_t key_id;
//     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
//     uint8_t tmp_pubkey[TFN_PUBKEY_EXPORT_LEN];
//     size_t tmp_len = 0;

//     /* Configure attributes for an ECC key pair (secp256r1) */
//     psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
//     psa_set_key_bits(&attr, 256);
//     psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
//     psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

//     /* Generate keypair inside secure partition */
//     status = psa_generate_key(&attr, &key_id);
//     psa_reset_key_attributes(&attr);
//     if (status != PSA_SUCCESS) {
//         return status;
//     }
//     sec_ble_key_id = key_id;

//     /* Client must provide enough out buffer space for the exported public key */
//     if (msg->out_size[0] < (sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN)) {
//         /* not enough space in client's out buffer */
//         /* optional: destroy key if you want ephemeral key */
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }




//     /* Export public key (format: 0x04 || X || Y) */
//     status = psa_export_public_key(key_id, tmp_pubkey, sizeof(tmp_pubkey), &tmp_len);
//     if (status != PSA_SUCCESS) {
//         psa_destroy_key(key_id);
//         return status;
//     }

//     /* Optionally keep the key (persistent) — here we keep it (key_id remains valid).
//        If you want ephemeral keys, destroy the key here:
//        psa_destroy_key(key_id);
//     */

//     /* Write exported public key back to the caller */
//       {
//         uint8_t outbuf[sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN];
//         size_t out_len = 0;

//         memcpy(outbuf, &key_id, sizeof(key_id));
//         memcpy(&outbuf[sizeof(key_id)], tmp_pubkey, tmp_len);
//         out_len = sizeof(key_id) + tmp_len;

//         psa_write(msg->handle, 0, outbuf, out_len);
//     }

//     return PSA_SUCCESS;
// }

        
// // keygeneration

// // Structure to hold a single secret (16 bytes)
// struct dp_secret {
//     uint8_t secret[16];
// };

// // Array of secrets initialized with test values
// struct dp_secret secrets[NUM_SECRETS] = {
//     { {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
//     { {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
//     { {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
//     { {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
//     { {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// };

// // Callback type definition for writing computed digests
// typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
//                                      uint32_t digest_size);

// /* -------------------- Secret Digest Service -------------------- */
// // Computes SHA-256 digest of a selected secret and writes it using a callback
// static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
//             size_t digest_size, size_t *p_digest_size,
//             psa_write_callback_t callback, void *handle)
// {
//     uint8_t digest[32];                      // Buffer for SHA-256 digest (32 bytes)
//     psa_status_t status;

//     if (secret_index >= NUM_SECRETS) {       // Validate secret index
//         return PSA_ERROR_INVALID_ARGUMENT;
//     }

//     if (digest_size != sizeof(digest)) {     // Ensure requested size matches SHA-256 size
//         return PSA_ERROR_INVALID_ARGUMENT;
//     }

//     // Compute SHA-256 hash of the secret
//     status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
//                 sizeof(secrets[secret_index].secret), digest,
//                 digest_size, p_digest_size);

//     if (status != PSA_SUCCESS) {             // Return if hashing failed
//         return status;
//     }
//     if (*p_digest_size != digest_size) {     // Ensure digest size matches expected size
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     callback(handle, digest, digest_size);   // Write digest via callback function

//     return PSA_SUCCESS;
// }

// // Callback function: writes the digest to client response buffer
// static void psa_write_digest(void *handle, uint8_t *digest,
//                              uint32_t digest_size)
// {
//     psa_write((psa_handle_t)handle, 0, digest, digest_size);
// }

// // IPC handler for Secret Digest requests
// static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
// {
//     size_t num = 0;
//     uint32_t secret_index;

//     if (msg->in_size[0] != sizeof(secret_index)) {   // Validate input size
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     // Read secret_index from client input
//     num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
//     if (num != msg->in_size[0]) {                    // Validate read size
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     // Call digest computation service with IPC context
//     return tfm_dp_secret_digest(secret_index, msg->out_size[0],
//                                 &msg->out_size[0], psa_write_digest,
//                                 (void *)msg->handle);
// }

// /* -------------------- Jasmine Service -------------------- */
// // IPC handler for Jasmine service (sends a static message to client)
// static psa_status_t tfm_jas_hi_service_ipc(psa_msg_t *msg)
// {
//     const char hi_msg[] = "Hi, I'm Jasmine, I like pizzaaaaaaaaaa and sleep";

//     if (msg->out_size[0] < sizeof(hi_msg)) { // Ensure client provided enough space
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     psa_write(msg->handle, 0, hi_msg, sizeof(hi_msg)); // Write static message to client

//     return PSA_SUCCESS;
// }

// /* -------------------- Dispatcher -------------------- */
// // Generic type for service handler functions
// typedef psa_status_t (*dp_func_t)(psa_msg_t *msg);

// // Handles incoming signals for a given service
// static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
// {
//     psa_status_t status;
//     psa_msg_t msg;

//     status = psa_get(signal, &msg);          // Get message for the signal
//     switch (msg.type) {
//     case PSA_IPC_CONNECT:                    // Connection request
//         psa_reply(msg.handle, PSA_SUCCESS);
//         break;
//     case PSA_IPC_CALL:                       // Service call
//         status = pfn(&msg);                  // Call the provided handler
//         psa_reply(msg.handle, status);       // Send back the result
//         break;
//     case PSA_IPC_DISCONNECT:                 // Disconnection request
//         psa_reply(msg.handle, PSA_SUCCESS);
//         break;
//     default:                                 // Unexpected message type
//         psa_panic();
//     }
// }


// // psa_status_t tfm_dp_req_mngr_init(void)
// // {
// //     psa_signal_t signals = 0;

// //     while (1) {
// //         signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK); // Wait for any incoming signal (blocking)

// //         if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {     // Secret Digest request
// //             dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// //                              tfm_dp_secret_digest_ipc);
// //         } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) { // Jasmine service request
// //             dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
// //                              tfm_jas_hi_service_ipc);
// //         } else {                                        // Unknown signal
// //             psa_panic();
// //         }
// //     }

// //     return PSA_ERROR_SERVICE_FAILURE; // Should never reach here
// // }

// //i comment the above function and usee the below


// //keygen




// // -------------------- BLE ECDH Service --------------------
// static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg)
// {
//     psa_status_t status;
//     uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN];
//     size_t num_bytes = 0;

//     // Validate input/output sizes
//     if (msg->in_size[0] != TFN_PUBKEY_EXPORT_LEN || 
//         msg->out_size[0] < TFN_ECDH_SHARED_KEY_LEN) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     // Read remote public key from non-secure world
//     num_bytes = psa_read(msg->handle, 0, remote_pub, msg->in_size[0]);
//     if (num_bytes != msg->in_size[0]) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     // Prepare output buffer for DH key
//     uint8_t dhkey[TFN_ECDH_SHARED_KEY_LEN];
//     size_t dhkey_len = 0;

//     // Perform raw key agreement inside secure partition
//     status = psa_raw_key_agreement(PSA_ALG_ECDH, sec_ble_key_id,
//                                    remote_pub, sizeof(remote_pub),
//                                    dhkey, sizeof(dhkey), &dhkey_len);
//     if (status != PSA_SUCCESS) {
//         return status;
//     }

//     // Return shared key to non-secure world
//     psa_write(msg->handle, 0, dhkey, dhkey_len);

//     return PSA_SUCCESS;
// }



// psa_status_t tfm_dp_req_mngr_init(void)
// {
//     psa_signal_t signals = 0;

//     while (1) {
//         signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

//         if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
//             dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
//                              tfm_dp_secret_digest_ipc);
//         } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
//             dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
//                              tfm_jas_hi_service_ipc);
//         } else if (signals & TFM_BLE_KEYGEN_SERVICE_SIGNAL) {
//             dp_signal_handle(TFM_BLE_KEYGEN_SERVICE_SIGNAL,
//                              tfm_ble_keygen_service_ipc);
//         } else if (signals & TFM_BLE_ECDH_SERVICE_SIGNAL) {   // NEW
//             dp_signal_handle(TFM_BLE_ECDH_SERVICE_SIGNAL,
//                              tfm_ble_ecdh_service_ipc);
//         } else {
//             psa_panic();
//         }
//     }

//     return PSA_ERROR_SERVICE_FAILURE; // Should never reach here
// }








#include <psa/crypto.h>        // PSA Crypto API for hashing and cryptographic operations
#include <stdbool.h>           // Standard boolean type definitions
#include <stdint.h>            // Standard fixed-width integer types
#include <stdio.h>             // Standard I/O (not heavily used here but included)
#include "psa/service.h"       // PSA service API for secure partition communication
#include "psa_manifest/tfm_dummy_partition.h" // Manifest header for this dummy partition (service IDs, signals)


#define NUM_SECRETS 5                  // Total number of stored secrets
#define TFN_PUBKEY_EXPORT_LEN 65       // Key generation
#define TFN_ECDH_SHARED_KEY_LEN 32     // 256-bit shared secret

static psa_key_id_t sec_ble_key_id = 0; // 0 = invalid key
static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg);


/* -------------------- Key Generation Service -------------------- */
static psa_status_t tfm_ble_keygen_service_ipc(psa_msg_t *msg)
{
    psa_status_t status;
    psa_key_id_t key_id;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t tmp_pubkey[TFN_PUBKEY_EXPORT_LEN];
    size_t tmp_len = 0;

    // Log from SECURE WORLD using TF-M logging
    // Note: Secure world logging is often disabled in production for security

    // Configure attributes for an ECC key pair (secp256r1)
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    // Generate keypair inside secure partition
    status = psa_generate_key(&attr, &key_id);
    sec_ble_key_id = key_id;

    // Key generated successfully - ID stored in sec_ble_key_id
    psa_reset_key_attributes(&attr);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Client must provide enough out buffer space for the exported public key
    if (msg->out_size[0] < (sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    // Export public key (format: 0x04 || X || Y)
    status = psa_export_public_key(key_id, tmp_pubkey, sizeof(tmp_pubkey), &tmp_len);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(key_id);
        return status;
    }

    // Optionally keep the key (persistent) or destroy for ephemeral key

    // Write exported public key back to the caller
    {
        uint8_t outbuf[sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN];
        size_t out_len = 0;
        memcpy(outbuf, &key_id, sizeof(key_id));
        memcpy(&outbuf[sizeof(key_id)], tmp_pubkey, tmp_len);
        out_len = sizeof(key_id) + tmp_len;
        psa_write(msg->handle, 0, outbuf, out_len);
    }

    return PSA_SUCCESS;
}

/* -------------------- Secret Digest Service -------------------- */
struct dp_secret {
    uint8_t secret[16];
};

// Array of secrets initialized with test values
struct dp_secret secrets[NUM_SECRETS] = {
    { {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
    { {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
    { {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
    { {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
    { {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
};

// Callback type definition for writing computed digests
typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest, uint32_t digest_size);

// Computes SHA-256 digest of a selected secret and writes it using a callback
static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
                                         size_t digest_size,
                                         size_t *p_digest_size,
                                         psa_write_callback_t callback,
                                         void *handle)
{
    uint8_t digest[32]; // Buffer for SHA-256 digest
    psa_status_t status;

    if (secret_index >= NUM_SECRETS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (digest_size != sizeof(digest)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    // Compute SHA-256 hash of the secret
    status = psa_hash_compute(PSA_ALG_SHA_256,
                              secrets[secret_index].secret,
                              sizeof(secrets[secret_index].secret),
                              digest,
                              digest_size,
                              p_digest_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (*p_digest_size != digest_size) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    callback(handle, digest, digest_size); // Write digest via callback
    return PSA_SUCCESS;
}

// Callback function: writes the digest to client response buffer
static void psa_write_digest(void *handle, uint8_t *digest, uint32_t digest_size)
{
    psa_write((psa_handle_t)handle, 0, digest, digest_size);
}

// IPC handler for Secret Digest requests
static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
{
    size_t num = 0;
    uint32_t secret_index;

    if (msg->in_size[0] != sizeof(secret_index)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
    if (num != msg->in_size[0]) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    return tfm_dp_secret_digest(secret_index,
                                msg->out_size[0],
                                &msg->out_size[0],
                                psa_write_digest,
                                (void *)msg->handle);
}

/* -------------------- Jasmine Service -------------------- */
// IPC handler for Jasmine service (sends a static message to client)
static psa_status_t tfm_jas_hi_service_ipc(psa_msg_t *msg)
{
    const char hi_msg[] = "Hi, I'm Jasmine, I like pizzaaaaaaaaaa and sleep";

    if (msg->out_size[0] < sizeof(hi_msg)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    psa_write(msg->handle, 0, hi_msg, sizeof(hi_msg));
    return PSA_SUCCESS;
}

/* -------------------- Dispatcher -------------------- */
typedef psa_status_t (*dp_func_t)(psa_msg_t *msg);

// Handles incoming signals for a given service
static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
{
    psa_status_t status;
    psa_msg_t msg;

    status = psa_get(signal, &msg);

    switch (msg.type) {
        case PSA_IPC_CONNECT:
            psa_reply(msg.handle, PSA_SUCCESS);
            break;
        case PSA_IPC_CALL:
            status = pfn(&msg);
            psa_reply(msg.handle, status);
            break;
        case PSA_IPC_DISCONNECT:
            psa_reply(msg.handle, PSA_SUCCESS);
            break;
        default:
            psa_panic();
    }
}


/* -------------------- ECDH Service -------------------- */
static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg)
{
    psa_status_t status;
    uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN];
    uint8_t shared[TFN_ECDH_SHARED_KEY_LEN];
    size_t out_len = 0;

    if (msg->in_size[0] != TFN_PUBKEY_EXPORT_LEN) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    // Read remote public key (65 bytes: 0x04 || X || Y)
    size_t num = psa_read(msg->handle, 0, remote_pub, sizeof(remote_pub));
    if (num != sizeof(remote_pub)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    if (sec_ble_key_id == 0) {
        return PSA_ERROR_BAD_STATE; // no private key generated yet
    }

    // Do raw key agreement
    status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                   sec_ble_key_id,
                                   remote_pub, sizeof(remote_pub),
                                   shared, sizeof(shared),
                                   &out_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    // Return shared secret (32 bytes) to non-secure side
    psa_write(msg->handle, 0, shared, out_len);
    return PSA_SUCCESS;
}

/* -------------------- Main Request Manager -------------------- */
psa_status_t tfm_dp_req_mngr_init(void)
{
    psa_signal_t signals = 0;

    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

        if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
            dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL, tfm_dp_secret_digest_ipc);
        } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
            dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL, tfm_jas_hi_service_ipc);
        } else if (signals & TFM_BLE_KEYGEN_SERVICE_SIGNAL) {
            dp_signal_handle(TFM_BLE_KEYGEN_SERVICE_SIGNAL, tfm_ble_keygen_service_ipc);
        } else if (signals & TFM_BLE_ECDH_SERVICE_SIGNAL) {
            dp_signal_handle(TFM_BLE_ECDH_SERVICE_SIGNAL, tfm_ble_ecdh_service_ipc); //yo hale
        }
        else {
            psa_panic();
        }
    }

    return PSA_ERROR_SERVICE_FAILURE; // Should never reach here
}
