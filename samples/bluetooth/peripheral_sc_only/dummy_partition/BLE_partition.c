/*
 * Copyright (c) 2021 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <psa/crypto.h>
#include "psa/service.h"
#include "psa_manifest/tfm_dummy_partition.h"

#define NUM_SECRETS 5
#define TFN_PUBKEY_EXPORT_LEN 65
#define TFN_ECDH_SHARED_KEY_LEN 32
#define MAX_BLE_CONNECTIONS 4

// Simplified key storage for multiple BLE connections
// Keys are indexed by dh_key_id (no slot allocation needed)
struct secure_key_entry {
    psa_key_id_t dh_key_id;     // 0 = unused, non-zero = in use (lookup key)
    uint8_t mackey[16];         // MacKey derived from F5 (stored securely)
    uint8_t ltk[16];            // LTK (Long-Term Key) derived from F5 (stored securely)
};

// Global key storage
static struct secure_key_entry sec_keys[MAX_BLE_CONNECTIONS];

// Helper: Find or create entry for a given dh_key_id
static struct secure_key_entry* find_or_create_entry(psa_key_id_t dh_key_id)
{
    // First, search for existing entry
    for (int i = 0; i < MAX_BLE_CONNECTIONS; i++) {
        if (sec_keys[i].dh_key_id == dh_key_id) {
            return &sec_keys[i];  // Found existing
        }
    }

    // Not found, find empty slot
    for (int i = 0; i < MAX_BLE_CONNECTIONS; i++) {
        if (sec_keys[i].dh_key_id == 0) {  // Empty (unused)
            sec_keys[i].dh_key_id = dh_key_id;  // Mark as used
            return &sec_keys[i];
        }
    }

    return NULL;  // No space available
}

// // struct dp_secret {
// // 	uint8_t secret[16];
// // };

// // struct dp_secret secrets[NUM_SECRETS] = {
// // 	{ {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // };

// // typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
// // 				     uint32_t digest_size);

// // static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
// // 			size_t digest_size, size_t *p_digest_size,
// // 			psa_write_callback_t callback, void *handle)
// // {
// // 	uint8_t digest[32];
// // 	psa_status_t status;

// // 	/* Check that secret_index is valid. */
// // 	if (secret_index >= NUM_SECRETS) {
// // 		return PSA_ERROR_INVALID_ARGUMENT;
// // 	}

// // 	/* Check that digest_size is valid. */
// // 	if (digest_size != sizeof(digest)) {
// // 		return PSA_ERROR_INVALID_ARGUMENT;
// // 	}

// // 	status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
// // 				sizeof(secrets[secret_index].secret), digest,
// // 				digest_size, p_digest_size);

// // 	if (status != PSA_SUCCESS) {
// // 		return status;
// // 	}
// // 	if (*p_digest_size != digest_size) {
// // 		return PSA_ERROR_PROGRAMMER_ERROR;
// // 	}

// // 	callback(handle, digest, digest_size);

// // 	return PSA_SUCCESS;
// // }

// // typedef psa_status_t (*dp_func_t)(psa_msg_t *);

// // static void psa_write_digest(void *handle, uint8_t *digest,
// // 			     uint32_t digest_size)
// // {
// // 	psa_write((psa_handle_t)handle, 0, digest, digest_size);
// // }

// // static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
// // {
// // 	size_t num = 0;
// // 	uint32_t secret_index;

// // 	if (msg->in_size[0] != sizeof(secret_index)) {
// // 		/* The size of the argument is incorrect */
// // 		return PSA_ERROR_PROGRAMMER_ERROR;
// // 	}

// // 	num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
// // 	if (num != msg->in_size[0]) {
// // 		return PSA_ERROR_PROGRAMMER_ERROR;
// // 	}

// // 	return tfm_dp_secret_digest(secret_index, msg->out_size[0],
// // 				    &msg->out_size[0], psa_write_digest,
// // 				    (void *)msg->handle);
// // }

// // static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
// // {
// // 	psa_status_t status;
// // 	psa_msg_t msg;

// // 	status = psa_get(signal, &msg);
// // 	switch (msg.type) {
// // 	case PSA_IPC_CONNECT:
// // 		psa_reply(msg.handle, PSA_SUCCESS);
// // 		break;
// // 	case PSA_IPC_CALL:
// // 		status = pfn(&msg);
// // 		psa_reply(msg.handle, status);
// // 		break;
// // 	case PSA_IPC_DISCONNECT:
// // 		psa_reply(msg.handle, PSA_SUCCESS);
// // 		break;
// // 	default:
// // 		psa_panic();
// // 	}
// // }

// // psa_status_t tfm_dp_req_mngr_init(void)
// // {
// // 	psa_signal_t signals = 0;

// // 	while (1) {
// // 		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
// // 		if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
// // 			dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// // 					 tfm_dp_secret_digest_ipc);
// // 		} else {
// // 			psa_panic();
// // 		}
// // 	}

// // 	return PSA_ERROR_SERVICE_FAILURE;
// // }




// // #include <psa/crypto.h>
// // #include <stdbool.h>
// // #include <stdint.h>
// // #include <stdio.h>

// // #include "psa/service.h"
// // #include "psa_manifest/tfm_dummy_partition.h" //dummy

// // #define NUM_SECRETS 5

// // struct dp_secret {
// // 	uint8_t secret[16];
// // };

// // struct dp_secret secrets[NUM_SECRETS] = {
// // 	{ {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // 	{ {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // };

// // typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
// // 				     uint32_t digest_size);

// // /* -------------------- Secret Digest Service -------------------- */
// // static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
// // 			size_t digest_size, size_t *p_digest_size,
// // 			psa_write_callback_t callback, void *handle)
// // {
// // 	uint8_t digest[32];
// // 	psa_status_t status;

// // 	if (secret_index >= NUM_SECRETS) {
// // 		return PSA_ERROR_INVALID_ARGUMENT;
// // 	}

// // 	if (digest_size != sizeof(digest)) {
// // 		return PSA_ERROR_INVALID_ARGUMENT;
// // 	}

// // 	status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
// // 				sizeof(secrets[secret_index].secret), digest,
// // 				digest_size, p_digest_size);

// // 	if (status != PSA_SUCCESS) {
// // 		return status;
// // 	}
// // 	if (*p_digest_size != digest_size) {
// // 		return PSA_ERROR_PROGRAMMER_ERROR;
// // 	}

// // 	callback(handle, digest, digest_size);

// // 	return PSA_SUCCESS;
// // }

// // static void psa_write_digest(void *handle, uint8_t *digest,
// // 			     uint32_t digest_size)
// // {
// // 	psa_write((psa_handle_t)handle, 0, digest, digest_size);
// // }

// // static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
// // {
// // 	size_t num = 0;
// // 	uint32_t secret_index;

// // 	if (msg->in_size[0] != sizeof(secret_index)) {
// // 		return PSA_ERROR_PROGRAMMER_ERROR;
// // 	}

// // 	num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
// // 	if (num != msg->in_size[0]) {
// // 		return PSA_ERROR_PROGRAMMER_ERROR;
// // 	}

// // 	return tfm_dp_secret_digest(secret_index, msg->out_size[0],
// // 				    &msg->out_size[0], psa_write_digest,
// // 				    (void *)msg->handle);
// // }

// // /* -------------------- Jasmine Service -------------------- */
// // static psa_status_t tfm_jas_hi_service_ipc(psa_msg_t *msg)
// // {
// // 	const char hi_msg[] = "Hi, I'm Jasmine, I like pizzaaaaaaaaaa and sleep";

// // 	if (msg->out_size[0] < sizeof(hi_msg)) {
// // 		return PSA_ERROR_PROGRAMMER_ERROR;
// // 	}

// // 	psa_write(msg->handle, 0, hi_msg, sizeof(hi_msg));

// // 	return PSA_SUCCESS;
// // }

// // /* -------------------- Dispatcher -------------------- */
// // typedef psa_status_t (*dp_func_t)(psa_msg_t *msg);

// // static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
// // {
// // 	psa_status_t status;
// // 	psa_msg_t msg;

// // 	status = psa_get(signal, &msg);
// // 	switch (msg.type) {
// // 	case PSA_IPC_CONNECT:
// // 		psa_reply(msg.handle, PSA_SUCCESS);
// // 		break;
// // 	case PSA_IPC_CALL:
// // 		status = pfn(&msg);
// // 		psa_reply(msg.handle, status);
// // 		break;
// // 	case PSA_IPC_DISCONNECT:
// // 		psa_reply(msg.handle, PSA_SUCCESS);
// // 		break;
// // 	default:
// // 		psa_panic();
// // 	}
// // }

// // psa_status_t tfm_dp_req_mngr_init(void)
// // {
// // 	psa_signal_t signals = 0;

// // 	while (1) {
// // 		signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

// // 		if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
// // 			dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// // 					 tfm_dp_secret_digest_ipc);
// // 		} else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
// // 			dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
// // 					 tfm_jas_hi_service_ipc);
// // 		} else {
// // 			psa_panic();
// // 		}
// // 	}

// // 	return PSA_ERROR_SERVICE_FAILURE;
// // }



















// // #include <psa/crypto.h>                     // PSA Crypto API for hashing and cryptographic operations
                      
// // #include <stdio.h>                          // Standard I/O (not heavily used here but included)
// // #include "psa/service.h"                    // PSA service API for secure partition communication
// // #include "psa_manifest/tfm_dummy_partition.h" // Manifest header for this dummy partition (service IDs, signals)

// // #define NUM_SECRETS 5                       // Total number of stored secrets
// // #define TFN_PUBKEY_EXPORT_LEN 65 //keygeneration

// // #define TFN_ECDH_SHARED_KEY_LEN 32  // 256-bit shared secret


// // static psa_key_id_t sec_ble_key_id = 0;  // 0 = invalid key




// // static psa_status_t tfm_ble_keygen_service_ipc(psa_msg_t *msg)
// // {
// //     psa_status_t status;
// //     psa_key_id_t key_id;
// //     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
// //     uint8_t tmp_pubkey[TFN_PUBKEY_EXPORT_LEN];
// //     size_t tmp_len = 0;

// //     /* Configure attributes for an ECC key pair (secp256r1) */
// //     psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
// //     psa_set_key_bits(&attr, 256);
// //     psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
// //     psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

// //     /* Generate keypair inside secure partition */
// //     status = psa_generate_key(&attr, &key_id);
// //     psa_reset_key_attributes(&attr);
// //     if (status != PSA_SUCCESS) {
// //         return status;
// //     }
// //     sec_ble_key_id = key_id;

// //     /* Client must provide enough out buffer space for the exported public key */
// //     if (msg->out_size[0] < (sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN)) {
// //         /* not enough space in client's out buffer */
// //         /* optional: destroy key if you want ephemeral key */
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }




// //     /* Export public key (format: 0x04 || X || Y) */
// //     status = psa_export_public_key(key_id, tmp_pubkey, sizeof(tmp_pubkey), &tmp_len);
// //     if (status != PSA_SUCCESS) {
// //         psa_destroy_key(key_id);
// //         return status;
// //     }

// //     /* Optionally keep the key (persistent) — here we keep it (key_id remains valid).
// //        If you want ephemeral keys, destroy the key here:
// //        psa_destroy_key(key_id);
// //     */

// //     /* Write exported public key back to the caller */
// //       {
// //         uint8_t outbuf[sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN];
// //         size_t out_len = 0;

// //         memcpy(outbuf, &key_id, sizeof(key_id));
// //         memcpy(&outbuf[sizeof(key_id)], tmp_pubkey, tmp_len);
// //         out_len = sizeof(key_id) + tmp_len;

// //         psa_write(msg->handle, 0, outbuf, out_len);
// //     }

// //     return PSA_SUCCESS;
// // }

        
// // // keygeneration

// // // Structure to hold a single secret (16 bytes)
// // struct dp_secret {
// //     uint8_t secret[16];
// // };

// // // Array of secrets initialized with test values
// // struct dp_secret secrets[NUM_SECRETS] = {
// //     { {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// //     { {1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// //     { {2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// //     { {3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// //     { {4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} },
// // };

// // // Callback type definition for writing computed digests
// // typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest,
// //                                      uint32_t digest_size);

// // /* -------------------- Secret Digest Service -------------------- */
// // // Computes SHA-256 digest of a selected secret and writes it using a callback
// // static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
// //             size_t digest_size, size_t *p_digest_size,
// //             psa_write_callback_t callback, void *handle)
// // {
// //     uint8_t digest[32];                      // Buffer for SHA-256 digest (32 bytes)
// //     psa_status_t status;

// //     if (secret_index >= NUM_SECRETS) {       // Validate secret index
// //         return PSA_ERROR_INVALID_ARGUMENT;
// //     }

// //     if (digest_size != sizeof(digest)) {     // Ensure requested size matches SHA-256 size
// //         return PSA_ERROR_INVALID_ARGUMENT;
// //     }

// //     // Compute SHA-256 hash of the secret
// //     status = psa_hash_compute(PSA_ALG_SHA_256, secrets[secret_index].secret,
// //                 sizeof(secrets[secret_index].secret), digest,
// //                 digest_size, p_digest_size);

// //     if (status != PSA_SUCCESS) {             // Return if hashing failed
// //         return status;
// //     }
// //     if (*p_digest_size != digest_size) {     // Ensure digest size matches expected size
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     callback(handle, digest, digest_size);   // Write digest via callback function

// //     return PSA_SUCCESS;
// // }

// // // Callback function: writes the digest to client response buffer
// // static void psa_write_digest(void *handle, uint8_t *digest,
// //                              uint32_t digest_size)
// // {
// //     psa_write((psa_handle_t)handle, 0, digest, digest_size);
// // }

// // // IPC handler for Secret Digest requests
// // static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
// // {
// //     size_t num = 0;
// //     uint32_t secret_index;

// //     if (msg->in_size[0] != sizeof(secret_index)) {   // Validate input size
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     // Read secret_index from client input
// //     num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
// //     if (num != msg->in_size[0]) {                    // Validate read size
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     // Call digest computation service with IPC context
// //     return tfm_dp_secret_digest(secret_index, msg->out_size[0],
// //                                 &msg->out_size[0], psa_write_digest,
// //                                 (void *)msg->handle);
// // }

// // /* -------------------- Jasmine Service -------------------- */
// // // IPC handler for Jasmine service (sends a static message to client)
// // static psa_status_t tfm_jas_hi_service_ipc(psa_msg_t *msg)
// // {
// //     const char hi_msg[] = "Hi, I'm Jasmine, I like pizzaaaaaaaaaa and sleep";

// //     if (msg->out_size[0] < sizeof(hi_msg)) { // Ensure client provided enough space
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     psa_write(msg->handle, 0, hi_msg, sizeof(hi_msg)); // Write static message to client

// //     return PSA_SUCCESS;
// // }

// // /* -------------------- Dispatcher -------------------- */
// // // Generic type for service handler functions
// // typedef psa_status_t (*dp_func_t)(psa_msg_t *msg);

// // // Handles incoming signals for a given service
// // static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
// // {
// //     psa_status_t status;
// //     psa_msg_t msg;

// //     status = psa_get(signal, &msg);          // Get message for the signal
// //     switch (msg.type) {
// //     case PSA_IPC_CONNECT:                    // Connection request
// //         psa_reply(msg.handle, PSA_SUCCESS);
// //         break;
// //     case PSA_IPC_CALL:                       // Service call
// //         status = pfn(&msg);                  // Call the provided handler
// //         psa_reply(msg.handle, status);       // Send back the result
// //         break;
// //     case PSA_IPC_DISCONNECT:                 // Disconnection request
// //         psa_reply(msg.handle, PSA_SUCCESS);
// //         break;
// //     default:                                 // Unexpected message type
// //         psa_panic();
// //     }
// // }


// // // psa_status_t tfm_dp_req_mngr_init(void)
// // // {
// // //     psa_signal_t signals = 0;

// // //     while (1) {
// // //         signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK); // Wait for any incoming signal (blocking)

// // //         if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {     // Secret Digest request
// // //             dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// // //                              tfm_dp_secret_digest_ipc);
// // //         } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) { // Jasmine service request
// // //             dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
// // //                              tfm_jas_hi_service_ipc);
// // //         } else {                                        // Unknown signal
// // //             psa_panic();
// // //         }
// // //     }

// // //     return PSA_ERROR_SERVICE_FAILURE; // Should never reach here
// // // }

// // //i comment the above function and usee the below


// // //keygen




// // // -------------------- BLE ECDH Service --------------------
// // static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg)
// // {
// //     psa_status_t status;
// //     uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN];
// //     size_t num_bytes = 0;

// //     // Validate input/output sizes
// //     if (msg->in_size[0] != TFN_PUBKEY_EXPORT_LEN || 
// //         msg->out_size[0] < TFN_ECDH_SHARED_KEY_LEN) {
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     // Read remote public key from non-secure world
// //     num_bytes = psa_read(msg->handle, 0, remote_pub, msg->in_size[0]);
// //     if (num_bytes != msg->in_size[0]) {
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     // Prepare output buffer for DH key
// //     uint8_t dhkey[TFN_ECDH_SHARED_KEY_LEN];
// //     size_t dhkey_len = 0;

// //     // Perform raw key agreement inside secure partition
// //     status = psa_raw_key_agreement(PSA_ALG_ECDH, sec_ble_key_id,
// //                                    remote_pub, sizeof(remote_pub),
// //                                    dhkey, sizeof(dhkey), &dhkey_len);
// //     if (status != PSA_SUCCESS) {
// //         return status;
// //     }

// //     // Return shared key to non-secure world
// //     psa_write(msg->handle, 0, dhkey, dhkey_len);

// //     return PSA_SUCCESS;
// // }



// // psa_status_t tfm_dp_req_mngr_init(void)
// // {
// //     psa_signal_t signals = 0;

// //     while (1) {
// //         signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

// //         if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
// //             dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
// //                              tfm_dp_secret_digest_ipc);
// //         } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
// //             dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
// //                              tfm_jas_hi_service_ipc);
// //         } else if (signals & TFM_BLE_KEYGEN_SERVICE_SIGNAL) {
// //             dp_signal_handle(TFM_BLE_KEYGEN_SERVICE_SIGNAL,
// //                              tfm_ble_keygen_service_ipc);
// //         } else if (signals & TFM_BLE_ECDH_SERVICE_SIGNAL) {   // NEW
// //             dp_signal_handle(TFM_BLE_ECDH_SERVICE_SIGNAL,
// //                              tfm_ble_ecdh_service_ipc);
// //         } else {
// //             psa_panic();
// //         }
// //     }

// //     return PSA_ERROR_SERVICE_FAILURE; // Should never reach here
// // }










// #include <psa/crypto.h>        // PSA Crypto API for hashing and cryptographic operations
// #include <stdbool.h>           // Standard boolean type definitions
// #include <stdint.h>            // Standard fixed-width integer types
// #include <stdio.h>             // Standard I/O (not heavily used here but included)
// #include "psa/service.h"       // PSA service API for secure partition communication
// #include "psa_manifest/tfm_dummy_partition.h" // Manifest header for this dummy partition (service IDs, signals)


// #define NUM_SECRETS 5                  // Total number of stored secrets
// #define TFN_PUBKEY_EXPORT_LEN 65       // Key generation
// #define TFN_ECDH_SHARED_KEY_LEN 32     // 256-bit shared secret

// // static psa_key_id_t sec_ble_key_id = 0; // 0 = invalid key 
// //adding more than one private keys

//   #define MAX_BLE_CONNECTIONS 4

//   struct ble_key_slot {
//       psa_key_id_t key_id;       // Private key handle (never leaves secure world)
//       uint8_t in_use;
//       uint8_t conn_index;
//       uint8_t dh_key[32];         // DH shared secret (stored securely, never returned)
//       uint8_t dh_key_valid;       // Flag: 1 if DH key has been computed
//       uint8_t mackey[16];         // MacKey derived from F5 (stored securely)
//       uint8_t ltk[16];            // LTK (Long-Term Key) derived from F5 (stored securely)
//       uint8_t f5_valid;           // Flag: 1 if F5 derivation completed
//   };


// static struct ble_key_slot sec_ble_keys[MAX_BLE_CONNECTIONS] = {0};

// // Find free slot
//   static int find_free_key_slot(void)
//   {
//       for (int i = 0; i < MAX_BLE_CONNECTIONS; i++) {
//           if (!sec_ble_keys[i].in_use) {
//               return i;
//           }
//       }
//       return -1;
//   }

//   // Find key by connection
//   static int find_key_by_conn(uint8_t conn_index)
//   {
//       for (int i = 0; i < MAX_BLE_CONNECTIONS; i++) {
//           if (sec_ble_keys[i].in_use &&
//               sec_ble_keys[i].conn_index == conn_index) {
//               return i;
//           }
//       }
//       return -1;
//   }

//   // Release key slot
//   static void release_key_slot(int slot_index)
//   {
//       if (slot_index >= 0 && slot_index < MAX_BLE_CONNECTIONS) {
//           if (sec_ble_keys[slot_index].key_id != 0) {
//               psa_destroy_key(sec_ble_keys[slot_index].key_id);
//           }
//           memset(&sec_ble_keys[slot_index], 0, sizeof(struct ble_key_slot));
//       }
//   }



// static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg);

// //adding more than one private key
// /* -------------------- Key Generation Service -------------------- */
// // static psa_status_t tfm_ble_keygen_service_ipc(psa_msg_t *msg)
// // {
// //     psa_status_t status;
// //     psa_key_id_t key_id;
// //     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
// //     uint8_t tmp_pubkey[TFN_PUBKEY_EXPORT_LEN];
// //     size_t tmp_len = 0;


// //     psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
// //     psa_set_key_bits(&attr, 256);
// //     psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
// //     psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

// //     // Generate keypair inside secure partition
// //     status = psa_generate_key(&attr, &key_id);
// //     sec_ble_key_id = key_id;

// //     // Key generated successfully - ID stored in sec_ble_key_id
// //     psa_reset_key_attributes(&attr);
// //     if (status != PSA_SUCCESS) {
// //         return status;
// //     }

// //     // Client must provide enough out buffer space for the exported public key
// //     if (msg->out_size[0] < (sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN)) {
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     // Export public key (format: 0x04 || X || Y)
// //     status = psa_export_public_key(key_id, tmp_pubkey, sizeof(tmp_pubkey), &tmp_len);
// //     if (status != PSA_SUCCESS) {
// //         psa_destroy_key(key_id);
// //         return status;
// //     }

// //     // Optionally keep the key (persistent) or destroy for ephemeral key

// //     // Write exported public key back to the caller
// //     {
// //         uint8_t outbuf[sizeof(key_id) + TFN_PUBKEY_EXPORT_LEN];
// //         size_t out_len = 0;
// //         memcpy(outbuf, &key_id, sizeof(key_id));
// //         memcpy(&outbuf[sizeof(key_id)], tmp_pubkey, tmp_len);
// //         out_len = sizeof(key_id) + tmp_len;
// //         psa_write(msg->handle, 0, outbuf, out_len);
// //     }

// //     return PSA_SUCCESS;
// // }
// //adding more than one private key

// struct keygen_input {
//       uint8_t conn_index;
//   };

//   struct keygen_output {
//       uint8_t slot_index;
//       uint8_t pubkey[TFN_PUBKEY_EXPORT_LEN];
//   };

//   static psa_status_t tfm_ble_keygen_service_ipc(psa_msg_t *msg)
//   {
//       psa_status_t status;
//       psa_key_id_t key_id;
//       psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
//       struct keygen_input input;
//       struct keygen_output output;
//       size_t tmp_len = 0;
//       int slot_index;

//       // Read connection index from non-secure
//       if (msg->in_size[0] != sizeof(input)) {
//           return PSA_ERROR_PROGRAMMER_ERROR;
//       }
//       size_t num = psa_read(msg->handle, 0, &input, sizeof(input));
//       if (num != sizeof(input)) {
//           return PSA_ERROR_PROGRAMMER_ERROR;
//       }

//       // Find free slot
//       slot_index = find_free_key_slot();
//       if (slot_index < 0) {
//           return PSA_ERROR_INSUFFICIENT_MEMORY;
//       }

//       // Generate key (same as before)
//       psa_set_key_type(&attr,
//   PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
//       psa_set_key_bits(&attr, 256);
//       psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_EXPORT |
//   PSA_KEY_USAGE_DERIVE);
//       psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

//       status = psa_generate_key(&attr, &key_id);
//       psa_reset_key_attributes(&attr);
//       if (status != PSA_SUCCESS) {
//           return status;
//       }

//       // Store in slot (NOT in global variable anymore!)
//       sec_ble_keys[slot_index].key_id = key_id;
//       sec_ble_keys[slot_index].in_use = 1;
//       sec_ble_keys[slot_index].conn_index = input.conn_index;

//       // Export public key
//       status = psa_export_public_key(key_id, output.pubkey,
//                                       sizeof(output.pubkey), &tmp_len);
//       if (status != PSA_SUCCESS) {
//           release_key_slot(slot_index);
//           return status;
//       }

//       // Return slot index + public key
//       output.slot_index = (uint8_t)slot_index;

//       if (msg->out_size[0] < sizeof(output)) {
//           release_key_slot(slot_index);
//           return PSA_ERROR_PROGRAMMER_ERROR;
//       }

//       psa_write(msg->handle, 0, &output, sizeof(output));
//       return PSA_SUCCESS;
//   }


// //untill here for adding more than one private key

// /* -------------------- Secret Digest Service -------------------- */
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
// typedef void (*psa_write_callback_t)(void *handle, uint8_t *digest, uint32_t digest_size);

// // Computes SHA-256 digest of a selected secret and writes it using a callback
// static psa_status_t tfm_dp_secret_digest(uint32_t secret_index,
//                                          size_t digest_size,
//                                          size_t *p_digest_size,
//                                          psa_write_callback_t callback,
//                                          void *handle)
// {
//     uint8_t digest[32]; // Buffer for SHA-256 digest
//     psa_status_t status;

//     if (secret_index >= NUM_SECRETS) {
//         return PSA_ERROR_INVALID_ARGUMENT;
//     }

//     if (digest_size != sizeof(digest)) {
//         return PSA_ERROR_INVALID_ARGUMENT;
//     }

//     // Compute SHA-256 hash of the secret
//     status = psa_hash_compute(PSA_ALG_SHA_256,
//                               secrets[secret_index].secret,
//                               sizeof(secrets[secret_index].secret),
//                               digest,
//                               digest_size,
//                               p_digest_size);
//     if (status != PSA_SUCCESS) {
//         return status;
//     }

//     if (*p_digest_size != digest_size) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     callback(handle, digest, digest_size); // Write digest via callback
//     return PSA_SUCCESS;
// }

// // Callback function: writes the digest to client response buffer
// static void psa_write_digest(void *handle, uint8_t *digest, uint32_t digest_size)
// {
//     psa_write((psa_handle_t)handle, 0, digest, digest_size);
// }

// // IPC handler for Secret Digest requests
// static psa_status_t tfm_dp_secret_digest_ipc(psa_msg_t *msg)
// {
//     size_t num = 0;
//     uint32_t secret_index;

//     if (msg->in_size[0] != sizeof(secret_index)) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     num = psa_read(msg->handle, 0, &secret_index, msg->in_size[0]);
//     if (num != msg->in_size[0]) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     return tfm_dp_secret_digest(secret_index,
//                                 msg->out_size[0],
//                                 &msg->out_size[0],
//                                 psa_write_digest,
//                                 (void *)msg->handle);
// }

// /* -------------------- Jasmine Service -------------------- */
// // IPC handler for Jasmine service (sends a static message to client)
// static psa_status_t tfm_jas_hi_service_ipc(psa_msg_t *msg)
// {
//     const char hi_msg[] = "Hi, I'm Jasmine, I like pizzaaaaaaaaaa and sleep";

//     if (msg->out_size[0] < sizeof(hi_msg)) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     psa_write(msg->handle, 0, hi_msg, sizeof(hi_msg));
//     return PSA_SUCCESS;
// }

// /* -------------------- Dispatcher -------------------- */
// typedef psa_status_t (*dp_func_t)(psa_msg_t *msg);

// // Handles incoming signals for a given service
// static void dp_signal_handle(psa_signal_t signal, dp_func_t pfn)
// {
//     psa_status_t status;
//     psa_msg_t msg;

//     status = psa_get(signal, &msg);

//     switch (msg.type) {
//         case PSA_IPC_CONNECT:
//             psa_reply(msg.handle, PSA_SUCCESS);
//             break;
//         case PSA_IPC_CALL:
//             status = pfn(&msg);
//             psa_reply(msg.handle, status);
//             break;
//         case PSA_IPC_DISCONNECT:
//             psa_reply(msg.handle, PSA_SUCCESS);
//             break;
//         default:
//             psa_panic();
//     }
// }

// //adding more than one private key

// /* -------------------- ECDH Service -------------------- */
// // static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg)
// // {
// //     psa_status_t status;
// //     uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN];
// //     uint8_t shared[TFN_ECDH_SHARED_KEY_LEN];
// //     size_t out_len = 0;

// //     if (msg->in_size[0] != TFN_PUBKEY_EXPORT_LEN) {
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     // Read remote public key (65 bytes: 0x04 || X || Y)
// //     size_t num = psa_read(msg->handle, 0, remote_pub, sizeof(remote_pub));
// //     if (num != sizeof(remote_pub)) {
// //         return PSA_ERROR_PROGRAMMER_ERROR;
// //     }

// //     if (sec_ble_key_id == 0) {
// //         return PSA_ERROR_BAD_STATE; // no private key generated yet
// //     }

// //     // Do raw key agreement
// //     status = psa_raw_key_agreement(PSA_ALG_ECDH,
// //                                    sec_ble_key_id,
// //                                    remote_pub, sizeof(remote_pub),
// //                                    shared, sizeof(shared),
// //                                    &out_len);
// //     if (status != PSA_SUCCESS) {
// //         return status;
// //     }

// //     // Return shared secret (32 bytes) to non-secure side
// //     psa_write(msg->handle, 0, shared, out_len);
// //     return PSA_SUCCESS;
// // }
// //adding more than one private key

// struct ecdh_input {
//       uint8_t slot_index;
//       uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN];
//   };

//   static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg)
//   {
//       psa_status_t status;
//       struct ecdh_input input;
//       uint8_t shared[TFN_ECDH_SHARED_KEY_LEN];
//       size_t out_len = 0;

//       // Read input (slot_index + remote public key)
//       if (msg->in_size[0] != sizeof(input)) {
//           return PSA_ERROR_PROGRAMMER_ERROR;
//       }
//       size_t num = psa_read(msg->handle, 0, &input, sizeof(input));
//       if (num != sizeof(input)) {
//           return PSA_ERROR_PROGRAMMER_ERROR;
//       }

//       // Validate slot index
//       if (input.slot_index >= MAX_BLE_CONNECTIONS ||
//           !sec_ble_keys[input.slot_index].in_use) {
//           return PSA_ERROR_BAD_STATE;
//       }

//       // Get the private key for this connection
//       psa_key_id_t private_key = sec_ble_keys[input.slot_index].key_id;

//       // Do raw key agreement with the correct key
//       status = psa_raw_key_agreement(PSA_ALG_ECDH,
//                                      private_key,  // Use key from slot!
//                                      input.remote_pub,
//                                      sizeof(input.remote_pub),
//                                      shared, sizeof(shared),
//                                      &out_len);
//       if (status != PSA_SUCCESS) {
//           return status;
//       }

//       // DEBUG: Print DH key BEFORE storing
//       printf("[SECURE] ECDH computed for SLOT %u\n", input.slot_index);
//       printf("[SECURE] DH Key (32 bytes, BIG-ENDIAN):\n");
//       for (int i = 0; i < 32; i++) {
//           printf("%02x", shared[i]);
//           if ((i + 1) % 16 == 0) printf("\n");
//       }
//       printf("\n");

//       // SECURITY: Store DH key in secure partition, DO NOT return to non-secure world!
//       memcpy(sec_ble_keys[input.slot_index].dh_key, shared, sizeof(shared));
//       sec_ble_keys[input.slot_index].dh_key_valid = 1;

//       printf("[SECURE] DH Key stored in sec_ble_keys[%u].dh_key\n", input.slot_index);
//       printf("[SECURE] DH Key AFTER storing (verify same):\n");
//       for (int i = 0; i < 32; i++) {
//           printf("%02x", sec_ble_keys[input.slot_index].dh_key[i]);
//           if ((i + 1) % 16 == 0) printf("\n");
//       }
//       printf("\n");

//       // Return only SUCCESS status (DH key stays in secure world)
//       return PSA_SUCCESS;
//   }


// //until her for addingmore than one private key


/* -------------------- F5 Key Derivation Service -------------------- */
// Input structure for F5 service
struct f5_input {
    uint32_t dh_key_id;
    uint8_t n1[16];          // Local random (prnd)
    uint8_t n2[16];          // Remote random (rrnd)
    uint8_t a1[7];           // Address 1 (bt_addr_le_t is 7 bytes)
    uint8_t a2[7];           // Address 2
};

// F5 service - derives MacKey and LTK from DH key using PSA key ID
static psa_status_t tfm_ble_f5_service_ipc(psa_msg_t *msg)
{
    psa_status_t status;
    struct f5_input input;
    uint8_t salt[16] = {0x6c, 0x88, 0x83, 0x91, 0xaa, 0xf5, 0xa5, 0x38,
                        0x60, 0x37, 0x0b, 0xdb, 0x5a, 0x60, 0x83, 0xbe};
    uint8_t t[16];  // Intermediate key
    uint8_t output[32];  // Counter || key_id (13 bytes) || MacKey (16 bytes) || LTK (16 bytes)
    uint8_t key_id[4] = {0x62, 0x74, 0x6c, 0x65};  // "btle"
    size_t output_len;
    uint8_t dh_key[32];  // Buffer to hold exported DH key

    // Read input parameters from non-secure world
    if (msg->in_size[0] != sizeof(input)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }
    size_t num = psa_read(msg->handle, 0, &input, sizeof(input));
    if (num != sizeof(input)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    printf("[SECURE-F5] Received DH Key ID = %u (0x%08x)\n", input.dh_key_id, input.dh_key_id);

    // Find or create entry for this DH key ID
    struct secure_key_entry *entry = find_or_create_entry(input.dh_key_id);
    if (!entry) {
        printf("[SECURE-F5] ERROR: No space for DH Key ID %u\n", input.dh_key_id);
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    printf("[SECURE-F5] Using entry for DH key ID 0x%08x\n", input.dh_key_id);

    // Export DH key from PSA using key ID
    status = psa_export_key(input.dh_key_id, dh_key, sizeof(dh_key), &output_len);
    if (status != PSA_SUCCESS || output_len != 32) {
        printf("[SECURE-F5] ERROR: Failed to export DH key: %d\n", status);
        return status;
    }

    printf("[SECURE-F5] DH key exported successfully (32 bytes)\n");

    // F5 Key Derivation Function using CMAC-AES-128 (BLE Core Spec compliant)
    // Based on bt_crypto_f5() from Zephyr BLE stack

    // Step 1: T = AES-CMAC(salt, DH_key)
    // Import salt as AES key for CMAC
    psa_key_attributes_t salt_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t salt_key_id = 0;

    psa_set_key_usage_flags(&salt_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&salt_attr, PSA_ALG_CMAC);  // Use CMAC, not HMAC!
    psa_set_key_type(&salt_attr, PSA_KEY_TYPE_AES);   // AES, not HMAC type!
    psa_set_key_bits(&salt_attr, 128);                 // 128-bit AES

    status = psa_import_key(&salt_attr, salt, 16, &salt_key_id);
    if (status != PSA_SUCCESS) {
        printf("[SECURE] F5: Failed to import salt key: %d\n", status);
        return status;
    }

    // Compute T = CMAC(salt, DH_key)
    status = psa_mac_compute(
        salt_key_id,
        PSA_ALG_CMAC,
        dh_key, 32,  // Use exported DH key
        t, 16, &output_len
    );

    psa_destroy_key(salt_key_id);

    if (status != PSA_SUCCESS) {
        printf("[SECURE] F5: CMAC(salt, DH_key) failed: %d\n", status);
        return status;
    }

    printf("[SECURE] F5: Step 1 complete - T derived\n");

    // Step 2: Build message for MacKey derivation
    // m = counter || keyID || n1 || n2 || a1 || a2 || length
    // NOTE: bt_crypto_f5 uses sys_memcpy_swap for n1, n2, addresses
    uint8_t m[53];
    m[0] = 0x00;  // counter = 0 for MacKey
    m[1] = 0x62; m[2] = 0x74; m[3] = 0x6c; m[4] = 0x65;  // "btle"

    // Byte-swap n1
    for (int i = 0; i < 16; i++) {
        m[5 + i] = input.n1[15 - i];
    }
    // Byte-swap n2
    for (int i = 0; i < 16; i++) {
        m[21 + i] = input.n2[15 - i];
    }
    // Address a1: type (not swapped) + 6-byte address (swapped)
    m[37] = input.a1[0];  // type
    for (int i = 0; i < 6; i++) {
        m[38 + i] = input.a1[6 - i];  // swap address bytes
    }
    // Address a2: type (not swapped) + 6-byte address (swapped)
    m[44] = input.a2[0];  // type
    for (int i = 0; i < 6; i++) {
        m[45 + i] = input.a2[6 - i];  // swap address bytes
    }
    m[51] = 0x01; m[52] = 0x00;  // length = 256 bits

    // Import T as AES key for CMAC
    psa_key_attributes_t t_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t t_key_id = 0;

    psa_set_key_usage_flags(&t_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&t_attr, PSA_ALG_CMAC);
    psa_set_key_type(&t_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&t_attr, 128);

    status = psa_import_key(&t_attr, t, 16, &t_key_id);
    if (status != PSA_SUCCESS) {
        printf("[SECURE] F5: Failed to import T key: %d\n", status);
        return status;
    }

    // Compute MacKey = CMAC(T, m with counter=0)
    status = psa_mac_compute(
        t_key_id,
        PSA_ALG_CMAC,
        m, sizeof(m),
        entry->mackey, 16, &output_len
    );

    if (status != PSA_SUCCESS) {
        psa_destroy_key(t_key_id);
        printf("[SECURE] F5: MacKey derivation failed: %d\n", status);
        return status;
    }

    printf("[SECURE-F5] MacKey derived\n");

    // Byte swap MacKey (as done in bt_crypto_f5)
    for (int i = 0; i < 8; i++) {
        uint8_t temp = entry->mackey[i];
        entry->mackey[i] = entry->mackey[15 - i];
        entry->mackey[15 - i] = temp;
    }

    // Step 3: Derive LTK with counter = 1
    m[0] = 0x01;  // counter = 1 for LTK

    status = psa_mac_compute(
        t_key_id,
        PSA_ALG_CMAC,
        m, sizeof(m),
        entry->ltk, 16, &output_len
    );

    psa_destroy_key(t_key_id);

    if (status != PSA_SUCCESS) {
        printf("[SECURE] F5: LTK derivation failed: %d\n", status);
        return status;
    }

    // Byte swap LTK (as done in bt_crypto_f5)
    for (int i = 0; i < 8; i++) {
        uint8_t temp = entry->ltk[i];
        entry->ltk[i] = entry->ltk[15 - i];
        entry->ltk[15 - i] = temp;
    }

    printf("[SECURE-F5] ✓ MacKey and LTK derived for DH Key ID 0x%08x\n", input.dh_key_id);

    return PSA_SUCCESS;
}

// -------------------- BLE F6 Service (DHKey Check) --------------------
struct f6_input {
    uint32_t dh_key_id;      // DH Key ID to lookup MacKey
    uint8_t n1[16];          // Nonce 1
    uint8_t n2[16];          // Nonce 2
    uint8_t r[16];           // R value
    uint8_t iocap[3];        // IO Capabilities
    uint8_t a1[7];           // Address 1 (bt_addr_le_t)
    uint8_t a2[7];           // Address 2 (bt_addr_le_t)
};

static psa_status_t tfm_ble_f6_service_ipc(psa_msg_t *msg)
{
    psa_status_t status;
    struct f6_input input;
    uint8_t check[16];       // Output: 16-byte check value
    uint8_t m[65];           // Message to MAC
    size_t output_len;

    // Read input from non-secure world
    if (msg->in_size[0] != sizeof(input)) {
        printf("[SECURE-F6] ERROR - Invalid input size\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t bytes_read = psa_read(msg->handle, 0, &input, sizeof(input));
    if (bytes_read != sizeof(input)) {
        printf("[SECURE-F6] ERROR - Failed to read input\n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    printf("[SECURE-F6] Received DH Key ID = %u (0x%08x)\n", input.dh_key_id, input.dh_key_id);

    // Find entry for this DH key ID
    struct secure_key_entry *entry = find_or_create_entry(input.dh_key_id);
    if (!entry) {
        printf("[SECURE-F6] ERROR: DH Key ID %u not found\n", input.dh_key_id);
        return PSA_ERROR_BAD_STATE;
    }

    printf("[SECURE-F6] Using entry for DH key ID 0x%08x\n", input.dh_key_id);

    // Build message according to BLE spec (same as bt_crypto_f6)
    // m = n1 || n2 || r || iocap || a1 || a2
    // NOTE: bt_crypto_f6 uses sys_memcpy_swap for n1, n2, r, iocap, addresses
    // We need to do the same byte swapping here

    // Swap n1
    for (int i = 0; i < 16; i++) {
        m[i] = input.n1[15 - i];
    }
    // Swap n2
    for (int i = 0; i < 16; i++) {
        m[16 + i] = input.n2[15 - i];
    }
    // Swap r
    for (int i = 0; i < 16; i++) {
        m[32 + i] = input.r[15 - i];
    }
    // Swap iocap (3 bytes)
    for (int i = 0; i < 3; i++) {
        m[48 + i] = input.iocap[2 - i];
    }
    // Copy a1 with swap (7 bytes)
    m[51] = input.a1[0];  // type byte (not swapped)
    for (int i = 0; i < 6; i++) {
        m[52 + i] = input.a1[6 - i];  // swap address bytes
    }
    // Copy a2 with swap (7 bytes)
    m[58] = input.a2[0];  // type byte (not swapped)
    for (int i = 0; i < 6; i++) {
        m[59 + i] = input.a2[6 - i];  // swap address bytes
    }

    printf("[SECURE] F6: Computing check value using CMAC...\n");

    // Byte-swap MacKey before using it (as done in bt_crypto_f6 line 146)
    uint8_t mackey_swapped[16];
    for (int i = 0; i < 16; i++) {
        mackey_swapped[i] = entry->mackey[15 - i];
    }

    // Import byte-swapped MacKey as AES key for CMAC
    psa_key_attributes_t mackey_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t mackey_id = 0;

    psa_set_key_usage_flags(&mackey_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&mackey_attr, PSA_ALG_CMAC);
    psa_set_key_type(&mackey_attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&mackey_attr, 128);

    status = psa_import_key(&mackey_attr, mackey_swapped, 16, &mackey_id);
    if (status != PSA_SUCCESS) {
        printf("[SECURE] F6: ERROR - Failed to import MacKey: %d\n", status);
        return status;
    }

    // Compute check = CMAC(MacKey, m)
    status = psa_mac_compute(
        mackey_id,
        PSA_ALG_CMAC,
        m, sizeof(m),
        check, 16, &output_len
    );

    psa_destroy_key(mackey_id);

    if (status != PSA_SUCCESS) {
        printf("[SECURE] F6: ERROR - CMAC computation failed: %d\n", status);
        return status;
    }

    if (output_len != 16) {
        printf("[SECURE] F6: ERROR - Unexpected output length: %zu\n", output_len);
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Byte-swap check value before returning (as done in bt_crypto_f6 line 155)
    for (int i = 0; i < 8; i++) {
        uint8_t temp = check[i];
        check[i] = check[15 - i];
        check[15 - i] = temp;
    }

    // Write byte-swapped check value to non-secure world
    psa_write(msg->handle, 0, check, 16);

    printf("[SECURE] F6: ✓ Check value computed and byte-swapped!\n");
    printf("[SECURE] F6: Returning 16-byte check value (MacKey stays secure)\n");

    return PSA_SUCCESS;
}

// -------------------- BLE GET_LTK Service --------------------
struct get_ltk_input {
    uint32_t dh_key_id;      // DH Key ID to lookup LTK
};

static psa_status_t tfm_ble_get_ltk_service_ipc(psa_msg_t *msg)
{
    struct get_ltk_input input;

    // Read input from non-secure world
    if (msg->in_size[0] != sizeof(input)) {
        printf("[SECURE-GET_LTK] ERROR - Invalid input size\n");
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    size_t bytes_read = psa_read(msg->handle, 0, &input, sizeof(input));
    if (bytes_read != sizeof(input)) {
        printf("[SECURE-GET_LTK] ERROR - Failed to read input\n");
        return PSA_ERROR_GENERIC_ERROR;
    }

    printf("[SECURE-GET_LTK] Received DH Key ID = %u (0x%08x)\n", input.dh_key_id, input.dh_key_id);

    // Find entry for this DH key ID
    struct secure_key_entry *entry = find_or_create_entry(input.dh_key_id);
    if (!entry) {
        printf("[SECURE-GET_LTK] ERROR: DH Key ID %u not found\n", input.dh_key_id);
        return PSA_ERROR_BAD_STATE;
    }

    printf("[SECURE-GET_LTK] Using entry for DH key ID 0x%08x\n", input.dh_key_id);

    // Write LTK to non-secure world
    // NOTE: This is acceptable because controller needs LTK for encryption
    // MacKey stays secure, only LTK is returned
    psa_write(msg->handle, 0, entry->ltk, 16);

    printf("[SECURE-GET_LTK] ✓ LTK sent to non-secure world\n");

    return PSA_SUCCESS;
}


// //I commented below for adding more than one private keys

// /* -------------------- Main Request Manager -------------------- */
// // psa_status_t tfm_dp_req_mngr_init(void)
// // {
// //     psa_signal_t signals = 0;

// //     while (1) {
// //         signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

// //         if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
// //             dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL, tfm_dp_secret_digest_ipc);
// //         } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
// //             dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL, tfm_jas_hi_service_ipc);
// //         } else if (signals & TFM_BLE_KEYGEN_SERVICE_SIGNAL) {
// //             dp_signal_handle(TFM_BLE_KEYGEN_SERVICE_SIGNAL, tfm_ble_keygen_service_ipc);
// //         } else if (signals & TFM_BLE_ECDH_SERVICE_SIGNAL) {
// //             dp_signal_handle(TFM_BLE_ECDH_SERVICE_SIGNAL, tfm_ble_ecdh_service_ipc); //yo hale
// //         }
// //         else {
// //             psa_panic();
// //         }
// //     }

// //     return PSA_ERROR_SERVICE_FAILURE; // Should never reach here
// // }

// psa_status_t tfm_dp_req_mngr_init(void)
//   {
//       psa_signal_t signals = 0;

//       while (1) {
//           signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

//           if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
//               dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
//   tfm_dp_secret_digest_ipc);
//           } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
//               dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
//   tfm_jas_hi_service_ipc);
//           } else if (signals & TFM_BLE_KEYGEN_SERVICE_SIGNAL) {
//               dp_signal_handle(TFM_BLE_KEYGEN_SERVICE_SIGNAL,
//   tfm_ble_keygen_service_ipc);
//           } else if (signals & TFM_BLE_ECDH_SERVICE_SIGNAL) {
//               dp_signal_handle(TFM_BLE_ECDH_SERVICE_SIGNAL,
//   tfm_ble_ecdh_service_ipc);
//           } else if (signals & TFM_BLE_F5_SERVICE_SIGNAL) {
//               dp_signal_handle(TFM_BLE_F5_SERVICE_SIGNAL,
//   tfm_ble_f5_service_ipc);
//           } else {
//               psa_panic();
//           }
//       }

//       return PSA_ERROR_SERVICE_FAILURE;
//   }





























// KEYGEN now has no input (just generates a new key)
  struct keygen_output {
      psa_key_id_t private_key_id;  // Return private key ID instead of slot_index
      uint8_t pubkey[TFN_PUBKEY_EXPORT_LEN];
  };

  static psa_status_t tfm_ble_keygen_service_ipc(psa_msg_t *msg)
  {
      psa_status_t status;
      psa_key_id_t key_id;
      psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
      struct keygen_output output;
      size_t tmp_len = 0;

      // No input needed - just generate a new key

      // Generate ECC keypair
      psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
      psa_set_key_bits(&attr, 256);
      psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
      psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

      status = psa_generate_key(&attr, &key_id);
      psa_reset_key_attributes(&attr);
      if (status != PSA_SUCCESS) {
          return status;
      }

      // Export public key
      status = psa_export_public_key(key_id, output.pubkey,
                                      sizeof(output.pubkey), &tmp_len);
      if (status != PSA_SUCCESS) {
          psa_destroy_key(key_id);
          return status;
      }

      // Return private key ID + public key
      output.private_key_id = key_id;

      if (msg->out_size[0] < sizeof(output)) {
          psa_destroy_key(key_id);
          return PSA_ERROR_PROGRAMMER_ERROR;
      }

      psa_write(msg->handle, 0, &output, sizeof(output));
      return PSA_SUCCESS;
  }


//untill here for adding more than one private key

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

//adding more than one private key

/* -------------------- ECDH Service -------------------- */
// static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg)
// {
//     psa_status_t status;
//     uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN];
//     uint8_t shared[TFN_ECDH_SHARED_KEY_LEN];
//     size_t out_len = 0;

//     if (msg->in_size[0] != TFN_PUBKEY_EXPORT_LEN) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     // Read remote public key (65 bytes: 0x04 || X || Y)
//     size_t num = psa_read(msg->handle, 0, remote_pub, sizeof(remote_pub));
//     if (num != sizeof(remote_pub)) {
//         return PSA_ERROR_PROGRAMMER_ERROR;
//     }

//     if (sec_ble_key_id == 0) {
//         return PSA_ERROR_BAD_STATE; // no private key generated yet
//     }

//     // Do raw key agreement
//     status = psa_raw_key_agreement(PSA_ALG_ECDH,
//                                    sec_ble_key_id,
//                                    remote_pub, sizeof(remote_pub),
//                                    shared, sizeof(shared),
//                                    &out_len);
//     if (status != PSA_SUCCESS) {
//         return status;
//     }

//     // Return shared secret (32 bytes) to non-secure side
//     psa_write(msg->handle, 0, shared, out_len);
//     return PSA_SUCCESS;
// }
//adding more than one private key

struct ecdh_input {
      psa_key_id_t private_key_id;  // Receive private key ID instead of slot_index
      uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN];
  };

  static psa_status_t tfm_ble_ecdh_service_ipc(psa_msg_t *msg)
  {
      psa_status_t status;
      struct ecdh_input input;
      uint8_t shared[TFN_ECDH_SHARED_KEY_LEN];
      size_t out_len = 0;

      // Read input (private_key_id + remote public key)
      if (msg->in_size[0] != sizeof(input)) {
          return PSA_ERROR_PROGRAMMER_ERROR;
      }
      size_t num = psa_read(msg->handle, 0, &input, sizeof(input));
      if (num != sizeof(input)) {
          return PSA_ERROR_PROGRAMMER_ERROR;
      }

      // Do raw key agreement using private key ID
      status = psa_raw_key_agreement(PSA_ALG_ECDH,
                                     input.private_key_id,
                                     input.remote_pub,
                                     sizeof(input.remote_pub),
                                     shared, sizeof(shared),
                                     &out_len);
      if (status != PSA_SUCCESS) {
          return status;
      }

      // STEP 1: Import DH key to PSA to get a key_id (PSA-only storage)
      psa_key_attributes_t dh_attr = PSA_KEY_ATTRIBUTES_INIT;
      psa_set_key_type(&dh_attr, PSA_KEY_TYPE_DERIVE);
      psa_set_key_bits(&dh_attr, 256);
      psa_set_key_usage_flags(&dh_attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
      psa_set_key_algorithm(&dh_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));

      psa_key_id_t dh_key_id;
      status = psa_import_key(&dh_attr, shared, sizeof(shared), &dh_key_id);
      psa_reset_key_attributes(&dh_attr);

      if (status != PSA_SUCCESS) {
          printf("[SECURE-ECDH] ERROR: Failed to import DH key: %d\n", status);
          return status;
      }

      // DH key ID will be stored by F5 when it's called (using find_or_create_entry)

      printf("\n========================================\n");
      printf("[SECURE-ECDH] ✓ DH key computed and imported to PSA\n");
      printf("[SECURE-ECDH] PSA assigned DH Key ID = %u (0x%08x)\n", dh_key_id, dh_key_id);
      printf("[SECURE-ECDH] DH key stored in PSA only (no raw bytes in memory)\n");
      printf("========================================\n\n");

      // STEP 2: Create handle buffer with DH key ID
      uint8_t dh_key_handle[32];
      memset(dh_key_handle, 0, 32);
      uint32_t dh_id_32bit = (uint32_t)dh_key_id;
      memcpy(dh_key_handle, &dh_id_32bit, sizeof(uint32_t));

      printf("[SECURE-ECDH] Created handle buffer:\n");
      printf("[SECURE-ECDH] First 4 bytes (DH Key ID): %02x %02x %02x %02x\n",
             dh_key_handle[0], dh_key_handle[1], dh_key_handle[2], dh_key_handle[3]);
      printf("[SECURE-ECDH] Sending 32-byte handle to ECC\n");

      // STEP 3: Return handle
      if (msg->out_size[0] < 32) {
          return PSA_ERROR_PROGRAMMER_ERROR;
      }
      psa_write(msg->handle, 0, dh_key_handle, 32);

      return PSA_SUCCESS;
  }

 
//until her for addingmore than one private key


//I commented below for adding more than one private keys

/* -------------------- Main Request Manager -------------------- */
// psa_status_t tfm_dp_req_mngr_init(void)
// {
//     psa_signal_t signals = 0;

//     while (1) {
//         signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

//         if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
//             dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL, tfm_dp_secret_digest_ipc);
//         } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
//             dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL, tfm_jas_hi_service_ipc);
//         } else if (signals & TFM_BLE_KEYGEN_SERVICE_SIGNAL) {
//             dp_signal_handle(TFM_BLE_KEYGEN_SERVICE_SIGNAL, tfm_ble_keygen_service_ipc);
//         } else if (signals & TFM_BLE_ECDH_SERVICE_SIGNAL) {
//             dp_signal_handle(TFM_BLE_ECDH_SERVICE_SIGNAL, tfm_ble_ecdh_service_ipc); //yo hale
//         }
//         else {
//             psa_panic();
//         }
//     }

//     return PSA_ERROR_SERVICE_FAILURE; // Should never reach here
// }

psa_status_t tfm_dp_req_mngr_init(void)
  {
      psa_signal_t signals = 0;

      while (1) {
          signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

          if (signals & TFM_DP_SECRET_DIGEST_SIGNAL) {
              dp_signal_handle(TFM_DP_SECRET_DIGEST_SIGNAL,
  tfm_dp_secret_digest_ipc);
          } else if (signals & TFM_JAS_HI_SERVICE_SIGNAL) {
              dp_signal_handle(TFM_JAS_HI_SERVICE_SIGNAL,
  tfm_jas_hi_service_ipc);
          } else if (signals & TFM_BLE_KEYGEN_SERVICE_SIGNAL) {
              dp_signal_handle(TFM_BLE_KEYGEN_SERVICE_SIGNAL,
  tfm_ble_keygen_service_ipc);
          } else if (signals & TFM_BLE_ECDH_SERVICE_SIGNAL) {
              dp_signal_handle(TFM_BLE_ECDH_SERVICE_SIGNAL,
  tfm_ble_ecdh_service_ipc);
          } else if (signals & TFM_BLE_F5_SERVICE_SIGNAL) {
              dp_signal_handle(TFM_BLE_F5_SERVICE_SIGNAL,
  tfm_ble_f5_service_ipc);
          } else if (signals & TFM_BLE_F6_SERVICE_SIGNAL) {
              dp_signal_handle(TFM_BLE_F6_SERVICE_SIGNAL,
  tfm_ble_f6_service_ipc);
          } else if (signals & TFM_BLE_GET_LTK_SERVICE_SIGNAL) {
              dp_signal_handle(TFM_BLE_GET_LTK_SERVICE_SIGNAL,
  tfm_ble_get_ltk_service_ipc);
          } else {
              psa_panic();
          }
      }

      return PSA_ERROR_SERVICE_FAILURE;
  }