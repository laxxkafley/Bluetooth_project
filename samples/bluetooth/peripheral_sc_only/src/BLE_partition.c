
#include <tfm_ns_interface.h>   // Provides interface for non-secure applications to call secure services
#include "BLE_partition.h"      // Header file for the BLE (dummy) secure partition
#include <stdbool.h>      // for bool
#include <zephyr/sys/slist.h>  // for sys_snode_t
#if defined(CONFIG_TFM_IPC)     // Compile this block only if Inter-Process Communication (IPC) is enabled
#include "psa/client.h"         // PSA client API used to communicate with secure partitions
#include "psa_manifest/sid.h"   // Contains Service IDs (SIDs) and versions for secure services
#include <string.h>
#include "psa/crypto.h"

#define TFN_PUBKEY_EXPORT_LEN 65  // 0x04 prefix + 64-byte X/Y coordinates for secp256r1


//keygen



//adding more than one private key
// psa_status_t dp_ble_keygen(uint8_t *out_buf, size_t buf_size, size_t *actual_export_len)
// {
//     psa_status_t status;
//     psa_handle_t handle;

//     psa_outvec out_vec[] = {
//         { .base = out_buf, .len = buf_size }
//     };

//     // handle = psa_connect(TFM_BLE_KEYGEN_SID, TFM_BLE_KEYGEN_VERSION);
//     handle = psa_connect(TFM_BLE_KEYGEN_SERVICE_SID,
//         TFM_BLE_KEYGEN_SERVICE_VERSION);

//     if (!PSA_HANDLE_IS_VALID(handle)) {
//         return PSA_ERROR_GENERIC_ERROR;
//     }

//     status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, 1);

//       if (status == PSA_SUCCESS && actual_export_len) {
//         /* out_vec[0].len contains number of bytes written by secure partition */
//         /* We return the length of the exported public key only (excluding key_id) */
//         if (out_vec[0].len >= sizeof(psa_key_id_t)) {
//             *actual_export_len = out_vec[0].len - sizeof(psa_key_id_t);
//         } else {
//             *actual_export_len = 0;
//         }
//     }

//     psa_close(handle);
//     return status;
// }
//adding more than one private key

// KEYGEN now returns private_key_id instead of slot_index
  struct keygen_output {
      psa_key_id_t private_key_id;
      uint8_t pubkey[65];  // TFN_PUBKEY_EXPORT_LEN
  };

  psa_status_t dp_ble_keygen(psa_key_id_t *private_key_id_out,
                             uint8_t *pub_key_out,
                             size_t *actual_export_len)
  {
      psa_status_t status;
      psa_handle_t handle;
      struct keygen_output output;

      psa_outvec out_vec[] = {
          { .base = &output, .len = sizeof(output) }
      };

      handle = psa_connect(TFM_BLE_KEYGEN_SERVICE_SID,
                           TFM_BLE_KEYGEN_SERVICE_VERSION);
      if (!PSA_HANDLE_IS_VALID(handle)) {
          return PSA_ERROR_GENERIC_ERROR;
      }

      // No input needed - just call to generate key
      status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec, 1);

      if (status == PSA_SUCCESS) {
          *private_key_id_out = output.private_key_id;
          memcpy(pub_key_out, output.pubkey, 65);
          if (actual_export_len) {
              *actual_export_len = 65;
          }
      }

      psa_close(handle);
      return status;
  }
//until here for adding more than one private keys




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


//adding more than one pirvate key

// -------------------- BLE ECDH Wrapper --------------------
// psa_status_t dp_ble_ecdh(const uint8_t remote_pub[TFN_PUBKEY_EXPORT_LEN],
//                          uint8_t *dhkey_out, size_t dhkey_size)
// {

//     if (!remote_pub || !dhkey_out) {
//         return PSA_ERROR_INVALID_ARGUMENT;
//     }

//     psa_status_t status;
//     psa_handle_t handle;
    

//     psa_invec in_vec[] = { 
//         { .base = (void *)remote_pub, .len = TFN_PUBKEY_EXPORT_LEN } 
//     };
//     psa_outvec out_vec[] = { 
//         { .base = dhkey_out, .len = dhkey_size } 
//     };

//     handle = psa_connect(TFM_BLE_ECDH_SERVICE_SID,
//                          TFM_BLE_ECDH_SERVICE_VERSION);
//     if (!PSA_HANDLE_IS_VALID(handle)) {
//         return PSA_ERROR_GENERIC_ERROR;
//     }

//     status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, out_vec, 1);

     
//     psa_close(handle);

//     return status;
// }
//adding more than one private key

struct ecdh_input {
      psa_key_id_t private_key_id;
      uint8_t remote_pub[65];  // TFN_PUBKEY_EXPORT_LEN
  };

  psa_status_t dp_ble_ecdh(psa_key_id_t private_key_id,
                           const uint8_t remote_pub[65],
                           uint8_t *dhkey_out,
                           size_t dhkey_size)
  {
      if (!remote_pub || !dhkey_out) {
          return PSA_ERROR_INVALID_ARGUMENT;
      }

      psa_status_t status;
      psa_handle_t handle;

      struct ecdh_input input = {
          .private_key_id = private_key_id
      };
      memcpy(input.remote_pub, remote_pub, 65);

      psa_invec in_vec[] = {
          { .base = &input, .len = sizeof(input) }
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

// F5 input structure (must match secure partition)
struct f5_input_ns {
    uint32_t dh_key_id;
    uint8_t n1[16];
    uint8_t n2[16];
    uint8_t a1[7];
    uint8_t a2[7];
};

psa_status_t dp_ble_f5(uint32_t dh_key_id,
                       const uint8_t n1[16],
                       const uint8_t n2[16],
                       const void *a1,
                       const void *a2)
{
    psa_status_t status;
    psa_handle_t handle;
    struct f5_input_ns input;

    // Prepare input structure
    input.dh_key_id = dh_key_id;
    memcpy(input.n1, n1, 16);
    memcpy(input.n2, n2, 16);
    memcpy(input.a1, a1, 7);  // bt_addr_le_t is 7 bytes
    memcpy(input.a2, a2, 7);

    psa_invec in_vec[] = {
        { .base = &input, .len = sizeof(input) }
    };
    // No output - MacKey and LTK stay in secure partition

    handle = psa_connect(TFM_BLE_F5_SERVICE_SID,
                         TFM_BLE_F5_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Only input, no output (keys stored in secure world)
    status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, NULL, 0);
    psa_close(handle);

    return status;
}

// F6 input structure (must match secure partition)
struct f6_input_ns {
    uint32_t dh_key_id;
    uint8_t n1[16];
    uint8_t n2[16];
    uint8_t r[16];
    uint8_t iocap[3];
    uint8_t a1[7];
    uint8_t a2[7];
};

psa_status_t dp_ble_f6(uint32_t dh_key_id,
                       const uint8_t n1[16],
                       const uint8_t n2[16],
                       const uint8_t r[16],
                       const uint8_t iocap[3],
                       const void *a1,
                       const void *a2,
                       uint8_t *check_out)
{
    psa_status_t status;
    psa_handle_t handle;
    struct f6_input_ns input;

    // Prepare input structure
    input.dh_key_id = dh_key_id;
    memcpy(input.n1, n1, 16);
    memcpy(input.n2, n2, 16);
    memcpy(input.r, r, 16);
    memcpy(input.iocap, iocap, 3);
    memcpy(input.a1, a1, 7);  // bt_addr_le_t is 7 bytes
    memcpy(input.a2, a2, 7);

    psa_invec in_vec[] = {
        { .base = &input, .len = sizeof(input) }
    };

    psa_outvec out_vec[] = {
        { .base = check_out, .len = 16 }  // F6 returns 16-byte check value
    };

    handle = psa_connect(TFM_BLE_F6_SERVICE_SID,
                         TFM_BLE_F6_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Send input, get check value output (MacKey stays in secure world)
    status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, out_vec, 1);
    psa_close(handle);

    return status;
}

// GET_LTK input structure (must match secure partition)
struct get_ltk_input_ns {
    uint32_t dh_key_id;
};

psa_status_t dp_ble_get_ltk(uint32_t dh_key_id, uint8_t *ltk_out)
{
    psa_status_t status;
    psa_handle_t handle;
    struct get_ltk_input_ns input;

    // Prepare input structure
    input.dh_key_id = dh_key_id;

    psa_invec in_vec[] = {
        { .base = &input, .len = sizeof(input) }
    };

    psa_outvec out_vec[] = {
        { .base = ltk_out, .len = 16 }  // Retrieve 16-byte LTK
    };

    handle = psa_connect(TFM_BLE_GET_LTK_SERVICE_SID,
                         TFM_BLE_GET_LTK_SERVICE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    // Send slot index, get LTK output
    status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, out_vec, 1);
    psa_close(handle);

    return status;
}

//until here for adding more than one private key


#else
/* Fallback if CONFIG_TFM_IPC not defined */ // This block is compiled if IPC is disabled
#endif