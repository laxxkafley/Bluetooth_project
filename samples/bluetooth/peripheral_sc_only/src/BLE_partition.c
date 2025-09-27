// /*
//  * Copyright (c) 2021 Nordic Semiconductor ASA.
//  *
//  * SPDX-License-Identifier: Apache-2.0
//  */

//  #include <tfm_ns_interface.h>

//  #include "dummy_partition.h"
 
//  #if defined(CONFIG_TFM_IPC)
//  #include "psa/client.h"
//  #include "psa_manifest/sid.h"
 
//  psa_status_t dp_secret_digest(uint32_t secret_index,
//              void *p_digest,
//              size_t digest_size)
//  {
//      psa_status_t status;
//      psa_handle_t handle;
 
//      psa_invec in_vec[] = {
//          { .base = &secret_index, .len = sizeof(secret_index) },
//      };
 
//      psa_outvec out_vec[] = {
//          { .base = p_digest, .len = digest_size }
//      };
 
//      handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
//                  TFM_DP_SECRET_DIGEST_VERSION);
//      if (!PSA_HANDLE_IS_VALID(handle)) {
//          return PSA_ERROR_GENERIC_ERROR;
//      }
 
//      status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec),
//              out_vec, IOVEC_LEN(out_vec));
 
//      psa_close(handle);
 
//      return status;
//  }
//  #else /* defined(CONFIG_TFM_IPC) */
//  psa_status_t dp_secret_digest(uint32_t secret_index,
//              void *p_digest,
//              size_t digest_size)
//  {
//      psa_status_t status;
//      psa_invec in_vec[] = {
//          { .base = &secret_index, .len = sizeof(secret_index) },
//      };
 
//      psa_outvec out_vec[] = {
//          { .base = p_digest, .len = digest_size }
//      };
 
//      status = tfm_ns_interface_dispatch(
//                  (veneer_fn)tfm_dp_secret_digest_req_veneer,
//                  (uint32_t)in_vec,  IOVEC_LEN(in_vec),
//                  (uint32_t)out_vec, IOVEC_LEN(out_vec));
 
//      return status;
//  }
//  #endif 

// #include <tfm_ns_interface.h>
// #include "BLE_partition.h" //dummy

// #if defined(CONFIG_TFM_IPC)
// #include "psa/client.h"
// #include "psa_manifest/sid.h"

// /* Wrapper for Secret Digest Service */
// psa_status_t dp_secret_digest(uint32_t secret_index,
//              void *p_digest,
//              size_t digest_size)
// {
//     psa_status_t status;
//     psa_handle_t handle;

//     psa_invec in_vec[] = {
//         { .base = &secret_index, .len = sizeof(secret_index) },
//     };
//     psa_outvec out_vec[] = {
//         { .base = p_digest, .len = digest_size }
//     };

//     handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
//                  TFM_DP_SECRET_DIGEST_VERSION);
//     if (!PSA_HANDLE_IS_VALID(handle)) {
//         return PSA_ERROR_GENERIC_ERROR;
//     }

//     status = psa_call(handle, PSA_IPC_CALL, in_vec, 1,
//              out_vec, 1);
//     psa_close(handle);

//     return status;
// }

// /* Wrapper for Jasmine Service */
// psa_status_t dp_jas_hi(char *buffer, size_t buf_size)
// {
//     psa_status_t status;
//     psa_handle_t handle;
//     psa_outvec out_vec[] = {
//         { .base = buffer, .len = buf_size }
//     };

//     handle = psa_connect(TFM_JAS_HI_SERVICE_SID,
//                          TFM_JAS_HI_SERVICE_VERSION);
//     if (!PSA_HANDLE_IS_VALID(handle)) {
//         return PSA_ERROR_GENERIC_ERROR;
//     }

//     status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, 1);
//     psa_close(handle);

//     return status;
// }

// #else
// /* Fallback if CONFIG_TFM_IPC not defined */
// #endif



#include <tfm_ns_interface.h>   // Provides interface for non-secure applications to call secure services
#include "BLE_partition.h"      // Header file for the BLE (dummy) secure partition
#include <stdbool.h>      // for bool
#include <zephyr/sys/slist.h>  // for sys_snode_t
#if defined(CONFIG_TFM_IPC)     // Compile this block only if Inter-Process Communication (IPC) is enabled
#include "psa/client.h"         // PSA client API used to communicate with secure partitions
#include "psa_manifest/sid.h"   // Contains Service IDs (SIDs) and versions for secure services
#include "psa/crypto.h"

#define TFN_PUBKEY_EXPORT_LEN 65  // 0x04 prefix + 64-byte X/Y coordinates for secp256r1


//keygen




psa_status_t dp_ble_keygen(uint8_t *out_buf, size_t buf_size, size_t *actual_export_len)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_outvec out_vec[] = {
        { .base = out_buf, .len = buf_size }
    };

    // handle = psa_connect(TFM_BLE_KEYGEN_SID, TFM_BLE_KEYGEN_VERSION);
    handle = psa_connect(TFM_BLE_KEYGEN_SERVICE_SID,
        TFM_BLE_KEYGEN_SERVICE_VERSION);

    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, 1);

      if (status == PSA_SUCCESS && actual_export_len) {
        /* out_vec[0].len contains number of bytes written by secure partition */
        /* We return the length of the exported public key only (excluding key_id) */
        if (out_vec[0].len >= sizeof(psa_key_id_t)) {
            *actual_export_len = out_vec[0].len - sizeof(psa_key_id_t);
        } else {
            *actual_export_len = 0;
        }
    }

    psa_close(handle);
    return status;
}







//keygen


/* Wrapper for Secret Digest Service */
psa_status_t dp_secret_digest(uint32_t secret_index,
             void *p_digest,
             size_t digest_size)
{
    psa_status_t status;        // Variable to store the result of PSA calls
    psa_handle_t handle;        // Handle used to connect to a secure service

    psa_invec in_vec[] = {      // Input vector: data to be sent to the secure service
        { .base = &secret_index, .len = sizeof(secret_index) }, // Send the secret index as input
    };
    psa_outvec out_vec[] = {    // Output vector: buffer to receive data from the secure service
        { .base = p_digest, .len = digest_size }                // Digest will be written into this buffer
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                 TFM_DP_SECRET_DIGEST_VERSION); // Connect to Secret Digest service using its SID and version
    if (!PSA_HANDLE_IS_VALID(handle)) {         // Check if the connection handle is valid
        return PSA_ERROR_GENERIC_ERROR;         // Return error if connection fails
    }

    status = psa_call(handle, PSA_IPC_CALL, in_vec, 1,
             out_vec, 1);       // Make the IPC call: send input and receive output
    psa_close(handle);          // Close the service connection after the call

    return status;              // Return the status of the secure call
}

/* Wrapper for Jasmine Service */
psa_status_t dp_jas_hi(char *buffer, size_t buf_size)
{
    psa_status_t status;        // Variable to store the result of PSA calls
    psa_handle_t handle;        // Handle used to connect to a secure service
    psa_outvec out_vec[] = {    // Output vector: buffer to receive data from the secure service
        { .base = buffer, .len = buf_size }                     // Response will be written into this buffer
    };

    handle = psa_connect(TFM_JAS_HI_SERVICE_SID,
                         TFM_JAS_HI_SERVICE_VERSION); // Connect to Jasmine service using its SID and version
    if (!PSA_HANDLE_IS_VALID(handle)) {              // Check if the connection handle is valid
        return PSA_ERROR_GENERIC_ERROR;              // Return error if connection fails
    }

    status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, 1); // Make the IPC call: no input, only output
    psa_close(handle);          // Close the service connection after the call

    return status;              // Return the status of the secure call
}

// -------------------- BLE ECDH Wrapper --------------------
psa_status_t dp_ble_ecdh(const uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN],
                         uint8_t *dhkey_out, size_t dhkey_size)
{

    if (!remote_pub || !dhkey_out) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    psa_status_t status;
    psa_handle_t handle;
    

    psa_invec in_vec[] = { 
        { .base = (void *)remote_pub, .len = TFN_PUBKEY_EXPORT_LEN } 
    };
    psa_outvec out_vec[] = { 
        { .base = dhkey_out, .len = dhkey_size } 
    };

    handle = psa_connect(TFM_BLE_ECDH_SERVICE_SID,
                         TFM_BLE_ECDH_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, out_vec, 1);

     
    psa_close(handle);

    return status;
}




#else
/* Fallback if CONFIG_TFM_IPC not defined */ // This block is compiled if IPC is disabled
#endif
