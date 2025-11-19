// /*
//  * Copyright (c) 2021 Nordic Semiconductor ASA.
//  *
//  * SPDX-License-Identifier: Apache-2.0
//  */

// //  psa_status_t dp_secret_digest(uint32_t secret_index,
// //     void *p_digest,
// //     size_t digest_size);



// // #ifndef DUMMY_PARTITION_H
// // #define DUMMY_PARTITION_H

// // #include <psa/client.h>
// // #include <stddef.h>
// // #include <stdint.h>

// // /* Existing function */
// // psa_status_t dp_secret_digest(uint32_t secret_index,
// //     void *p_digest,
// //     size_t digest_size);

// // /* New Jasmine function prototype */
// // psa_status_t dp_jas_hi(char *hi_msg, size_t msg_size);

// // #endif /* DUMMY_PARTITION_H */


// #ifndef DUMMY_PARTITION_H
// #define DUMMY_PARTITION_H

// #include <psa/client.h>
// #include <stddef.h>
// #include <stdint.h>
// #include "/home/jasmine/zephyrproject/zephyr/subsys/bluetooth/host/ecc.h"  // for BT_PUB_KEY_LEN and BT_DH_KEY_LEN
// #define TFN_PUBKEY_EXPORT_LEN 65
// #define TFN_ECDH_SHARED_KEY_LEN 32
// #include "psa/crypto.h"



// /* Existing function */
// psa_status_t dp_secret_digest(uint32_t secret_index,
//     void *p_digest,
//     size_t digest_size);

// /* New Jasmine function prototype */
// psa_status_t dp_jas_hi(char *hi_msg, size_t msg_size);

// //adding more tahn one private key
// /* BLE Keygen service prototype */
// // psa_status_t dp_ble_keygen(uint8_t *pub_key,
// //     size_t key_size,
// //     size_t *actual_export_len);

// // psa_status_t dp_ble_ecdh(const uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN],
// //                          uint8_t *dhkey_out, size_t dhkey_len);
// //adding more than one private key


//  /* BLE Keygen service prototype */
//   psa_status_t dp_ble_keygen(uint8_t conn_index,
//                              uint8_t *slot_index_out,
//                              uint8_t *pub_key_out,
//                              size_t *actual_export_len);

//   psa_status_t dp_ble_ecdh(uint8_t slot_index,
//                            const uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN]);

//   psa_status_t dp_ble_f5(uint8_t slot_index,
//                          const uint8_t n1[16],
//                          const uint8_t n2[16],
//                          const void *a1,
//                          const void *a2);


//   //until here for adding more than one private key


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

//adding more tahn one private key
/* BLE Keygen service prototype */
// psa_status_t dp_ble_keygen(uint8_t *pub_key,
//     size_t key_size,
//     size_t *actual_export_len);

// psa_status_t dp_ble_ecdh(const uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN],
//                          uint8_t *dhkey_out, size_t dhkey_len);
//adding more than one private key


 /* BLE Keygen service prototype */
  psa_status_t dp_ble_keygen(psa_key_id_t *private_key_id_out,
                             uint8_t *pub_key_out,
                             size_t *actual_export_len);

  psa_status_t dp_ble_ecdh(psa_key_id_t private_key_id,
                           const uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN],
                           uint8_t *dhkey_out,
                           size_t dhkey_len);

  psa_status_t dp_ble_f5(uint32_t dh_key_id,
                         const uint8_t n1[16],
                         const uint8_t n2[16],
                         const void *a1,
                         const void *a2);

  psa_status_t dp_ble_f6(uint32_t dh_key_id,
                         const uint8_t n1[16],
                         const uint8_t n2[16],
                         const uint8_t r[16],
                         const uint8_t iocap[3],
                         const void *a1,
                         const void *a2,
                         uint8_t *check_out);

  psa_status_t dp_ble_get_ltk(uint32_t dh_key_id, uint8_t *ltk_out);

  //until here for adding more than one private key


#endif /* DUMMY_PARTITION_H */
