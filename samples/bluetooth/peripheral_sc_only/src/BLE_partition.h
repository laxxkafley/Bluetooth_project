/*
 * Copyright (c) 2021 Nordic Semiconductor ASA.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//  psa_status_t dp_secret_digest(uint32_t secret_index,
//     void *p_digest,
//     size_t digest_size);



// #ifndef DUMMY_PARTITION_H
// #define DUMMY_PARTITION_H

// #include <psa/client.h>
// #include <stddef.h>
// #include <stdint.h>

// /* Existing function */
// psa_status_t dp_secret_digest(uint32_t secret_index,
//     void *p_digest,
//     size_t digest_size);

// /* New Jasmine function prototype */
// psa_status_t dp_jas_hi(char *hi_msg, size_t msg_size);

// #endif /* DUMMY_PARTITION_H */


#ifndef DUMMY_PARTITION_H
#define DUMMY_PARTITION_H

#include <psa/client.h>
#include <stddef.h>
#include <stdint.h>
#include "/home/jasmine/zephyrproject/zephyr/subsys/bluetooth/host/ecc.h"  // for BT_PUB_KEY_LEN and BT_DH_KEY_LEN
#define TFN_PUBKEY_EXPORT_LEN 65
#define TFN_ECDH_SHARED_KEY_LEN 32
#include "psa/crypto.h"



/* Existing function */
psa_status_t dp_secret_digest(uint32_t secret_index,
    void *p_digest,
    size_t digest_size);

/* New Jasmine function prototype */
psa_status_t dp_jas_hi(char *hi_msg, size_t msg_size);

/* BLE Keygen service prototype */
psa_status_t dp_ble_keygen(uint8_t *pub_key,
    size_t key_size,
    size_t *actual_export_len);

psa_status_t dp_ble_ecdh(const uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN],
                         uint8_t *dhkey_out, size_t dhkey_len);


#endif /* DUMMY_PARTITION_H */
