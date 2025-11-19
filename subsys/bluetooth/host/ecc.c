

//  #include <stdint.h>

//  #include <zephyr/sys/byteorder.h>
//  #include <zephyr/sys/check.h>
//  #include <zephyr/bluetooth/hci.h>
 
//  #include <psa/crypto.h>
 
//  #include "long_wq.h"
//  #include "ecc.h"
//  #include "hci_core.h"


// #include "/home/jasmine/zephyrproject/zephyr/samples/bluetooth/peripheral_sc_only/src/BLE_partition.h"

// //keygen



// #define TFN_PUBKEY_EXPORT_LEN 65  // Should match the secure partition





//  #define LOG_LEVEL CONFIG_BT_HCI_CORE_LOG_LEVEL
//  #include <zephyr/logging/log.h>
//  LOG_MODULE_REGISTER(bt_ecc);

//  //keygen
// //  void test_secure_pubkey(void)
// // {
// //     uint8_t sec_pub[TFN_PUBKEY_EXPORT_LEN] = {0};
// //     size_t actual_len = 0;

// //     psa_status_t status = dp_ble_keygen(sec_pub, sizeof(sec_pub), &actual_len);

// //     if (status == PSA_SUCCESS) {
// //         k_sleep(K_MSEC(100)); // optional: let logs flush

// //         LOG_INF("Secure Partition Public Key (len=%zu)", actual_len);
// //         LOG_HEXDUMP_INF(sec_pub, actual_len, "Secure Public Key");
// //     } else {
// //         LOG_INF("Secure call to get public key failed! Status: %d", status);
// //     }
// // }






//  //#define CONFIG_JASMIN_CHANGE
 
//  static uint8_t pub_key[BT_PUB_KEY_LEN];
//  // pub_key: Stores the ECC public key.
//  // pub_key_cb_slist: A linked list to hold callback functions for handling public key operations.
//  // dh_key_cb: A callback function for handling Diffie-Hellman (DH) key exchange.
//  static sys_slist_t pub_key_cb_slist;
//  static bt_dh_key_cb_t dh_key_cb;
 
//  static void generate_pub_key(struct k_work *work);
//  static void generate_dh_key(struct k_work *work);
//  K_WORK_DEFINE(pub_key_work, generate_pub_key);
//  K_WORK_DEFINE(dh_key_work, generate_dh_key);
 
//  enum {
// 	 PENDING_PUB_KEY,
// 	 PENDING_DHKEY,
 
// 	 /* Total number of flags - must be at the end of the enum */
// 	 NUM_FLAGS,
//  };
 
//  static ATOMIC_DEFINE(flags, NUM_FLAGS);
//  //Soring public and private key
//  static struct {
// 	 uint8_t private_key_be[BT_PRIV_KEY_LEN];
 
// 	 union {
// 		 uint8_t public_key_be[BT_PUB_KEY_LEN];
// 		 uint8_t dhkey_be[BT_DH_KEY_LEN];
// 	 };
//  } ecc;
//  static psa_key_id_t global_key_id; // lalalalalalalalallala


//  psa_key_id_t my_key_id;
 
//  // Predefined debug keys for testing ECC operations.
//  /* based on Core Specification 4.2 Vol 3. Part H 2.3.5.6.1 */
//  static const uint8_t debug_private_key_be[BT_PRIV_KEY_LEN] = {
// 	 0x3f, 0x49, 0xf6, 0xd4, 0xa3, 0xc5, 0x5f, 0x38,
// 	 0x74, 0xc9, 0xb3, 0xe3, 0xd2, 0x10, 0x3f, 0x50,
// 	 0x4a, 0xff, 0x60, 0x7b, 0xeb, 0x40, 0xb7, 0x99,
// 	 0x58, 0x99, 0xb8, 0xa6, 0xcd, 0x3c, 0x1a, 0xbd,
//  };
 
//  static const uint8_t debug_public_key[BT_PUB_KEY_LEN] = {
// 	 /* X */
// 	 0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc,
// 	 0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91, 0xf4, 0xef,
// 	 0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e,
// 	 0x2c, 0xbe, 0x97, 0xf2, 0xd2, 0x03, 0xb0, 0x20,
// 	 /* Y */
// 	 0x8b, 0xd2, 0x89, 0x15, 0xd0, 0x8e, 0x1c, 0x74,
// 	 0x24, 0x30, 0xed, 0x8f, 0xc2, 0x45, 0x63, 0x76,
// 	 0x5c, 0x15, 0x52, 0x5a, 0xbf, 0x9a, 0x32, 0x63,
// 	 0x6d, 0xeb, 0x2a, 0x65, 0x49, 0x9c, 0x80, 0xdc
//  };
 
//  // Compares a given public key with the predefined debug public key.
//  // Returns true if they match.
//  bool bt_pub_key_is_debug(uint8_t *cmp_pub_key)
//  {
// 	 return memcmp(cmp_pub_key, debug_public_key, BT_PUB_KEY_LEN) == 0;
//  }
 
//  // public key validation
 
//  bool bt_pub_key_is_valid(const uint8_t key[BT_PUB_KEY_LEN])
//  {
// 	 uint8_t key_be[BT_PUB_KEY_LEN + 1];
// 	 psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
// 	 psa_status_t ret;
// 	 psa_key_id_t handle;
 
// 	 psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
// 	 psa_set_key_bits(&attr, 256);
// 	 psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
// 	 psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
 
// 	 /* PSA expects secp256r1 public key to start with a predefined 0x04 byte */
// 	 key_be[0] = 0x04;
// 	 sys_memcpy_swap(&key_be[1], key, BT_PUB_KEY_COORD_LEN);
// 	 sys_memcpy_swap(&key_be[1 + BT_PUB_KEY_COORD_LEN], &key[BT_PUB_KEY_COORD_LEN],
// 			 BT_PUB_KEY_COORD_LEN);
 
// 	 ret = psa_import_key(&attr, key_be, sizeof(key_be), &handle);
// 	 psa_reset_key_attributes(&attr);
 
// 	 if (ret == PSA_SUCCESS) {
// 		 psa_destroy_key(handle);
// 		 return true;
// 	 }
 
// 	//  LOG_ERR("psa_import_key() returned status %d", ret);
// 	 return false;
//  }






//  // Configures ECC key attributes for key pair generation.
//  // The key:
 
//  //     Can be exported.
//  //     Can be used for key derivation (ECDH).
 
//  static void set_key_attributes(psa_key_attributes_t *attr)
//  {
// 	 psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
// 	 psa_set_key_bits(attr, 256);
// 	 #ifdef CONFIG_JASMIN_CHANGE
// 	 psa_set_key_usage_flags(attr, PSA_KEY_USAGE_DERIVE);
// 	 #else
// 	 psa_set_key_usage_flags(attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
// 	 #endif
// 	 psa_set_key_algorithm(attr, PSA_ALG_ECDH);
//  }
 
//  // Generating an ECC Public KeyCalls psa_generate_key() to create an ECC key pair.
//  // If the operation fails, logs an error and exits.
// //  LOG_INF("Calling generate_pub_key()...");



 
//  static void generate_pub_key(struct k_work *work)
//  {
// 	 LOG_INF("generate_pub_key() was triggered");
	

// 	 psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
// 	 struct bt_pub_key_cb *cb;
// 	 psa_key_id_t key_id;
// 	 uint8_t tmp_pub_key_buf[BT_PUB_KEY_LEN + 1];
// 	 size_t tmp_len;
// 	 int err;
// 	 psa_status_t ret;
 
// 	 set_key_attributes(&attr);
	 
	 
// 	 ret = psa_generate_key(&attr, &global_key_id); 

// 	 LOG_INF("psa_generate_key() returned: %d", ret);  // Add this line //jasmine
	
// 	 if (ret != PSA_SUCCESS) {
// 		 LOG_ERR("Failed to generate ECC key %d", ret);
// 		 err = BT_HCI_ERR_UNSPECIFIED;
// 		 goto done;
// 	 } 
 
// 	 ret = psa_export_public_key(global_key_id, tmp_pub_key_buf, sizeof(tmp_pub_key_buf), &tmp_len); //lalalalalalallala replace key_id
// 	 LOG_INF("psa_export_public_key() returned: %d", ret);  // Add this line //jasmine
// 	 if (ret != PSA_SUCCESS) {
// 		 LOG_ERR("Failed to export ECC public key %d", ret);
// 		 err = BT_HCI_ERR_UNSPECIFIED;
// 		 goto done;
// 	 }else {
// 		// Success - do something after successful key export
// 		// LOG_INF("EXPORTED ECC PUBLIC KEY");
// 		// LOG_HEXDUMP_INF(tmp_pub_key_buf, tmp_len, "Public Key Data");
// 	 }
// 	 /* secp256r1 PSA exported public key has an extra 0x04 predefined byte at
// 	  * the beginning of the buffer which is not part of the coordinate so
// 	  * we remove that.
// 	  */
	 
// 	  memcpy(ecc.public_key_be, &tmp_pub_key_buf[1], BT_PUB_KEY_LEN);// After copying the public key into ecc.public_key_be
// 	  LOG_INF("LOCAL PUBLLIC KEY after copying from buffer: ");
// 	   LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "local Public Key");//jasmine
	
	
	  
	 
	 
// //  // Exports the private key and stores it.
// // 	 ret = psa_export_key(key_id, ecc.private_key_be, BT_PRIV_KEY_LEN, &tmp_len);
// // 	 if (ret != PSA_SUCCESS) {
// // 		 LOG_ERR("Failed to export ECC private key %d", ret);
// // 		 err = BT_HCI_ERR_UNSPECIFIED;
// // 		 goto done;
// // 	 }


// 	//  // Destroys the generated key to ensure security.
// 	//  ret = psa_destroy_key(key_id);
// 	//  if (ret != PSA_SUCCESS) {
// 	// 	 LOG_ERR("Failed to destroy ECC key ID %d", ret);
// 	// 	 err = BT_HCI_ERR_UNSPECIFIED;
// 	// 	 goto done;
// 	//  }
 
// 	 // sys_memcpy_swap() is likely a helper function that copies and swaps the byte order from big-endian to little-endian.
 
// 	 sys_memcpy_swap(pub_key, ecc.public_key_be, BT_PUB_KEY_COORD_LEN);
// 	 sys_memcpy_swap(&pub_key[BT_PUB_KEY_COORD_LEN],
// 			 &ecc.public_key_be[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);
 
// 	 atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);
// 	 err = 0;
// 	 // atomic_set_bit() sets a specific bit in bt_dev.flags, marking that the public key is now available.
// 	 // Cleanup and Callback Execution
//  done:
// 	 atomic_clear_bit(flags, PENDING_PUB_KEY);

// 	 LOG_INF("Before generate_dh_key, see local PUBLIC KEY:");
// 	 LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "Public Key Data Before generate_dh_key");
 
// 	 /* Change to cooperative priority while we do the callbacks */
// 	 k_sched_lock();

	
 
// 	 SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
// 		 if (cb->func) {
// 			 cb->func(err ? NULL : pub_key);
// 		 }
// 	 }
 
// 	 sys_slist_init(&pub_key_cb_slist);
 
// 	 k_sched_unlock();
	 
//  }
 

//  // This function performs ECDH key agreement to derive a shared secret key.
//  static void generate_dh_key(struct k_work *work)
//  {
// 	// LOG_INF("YOOOOOOOOOOOOOOOOOOOOOOO i m hngry");
// 	 int err;
 
// 	 psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
// 	//  psa_key_id_t key_id;
// 	 psa_status_t ret;
	 
// 	 /* PSA expects secp256r1 public key to start with a predefined 0x04 byte
// 	  * at the beginning the buffer.
// 	  */
// 	 uint8_t tmp_pub_key_buf[BT_PUB_KEY_LEN + 1] = { 0x04 };
// 	 size_t tmp_len;
 
// 	 set_key_attributes(&attr);
	
	 
// 	 if(IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
// 		LOG_INF("Debug key is used.... We shouldnt use it....");
// 		LOG_INF("Debug Private Key: %s", debug_private_key_be);
// 	 } else {
// 		LOG_INF("Fresh ecc key was generated. and being used for dhkey...");
// 		LOG_INF("Generated Private Key: %s", ecc.private_key_be);
// 	 }
 
// 	 const uint8_t *priv_key = (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS) ?
// 					debug_private_key_be :
// 					ecc.private_key_be);


// 					//lalalal i commented import

			
					
// 	//  ret = psa_import_key(&attr, priv_key, BT_PRIV_KEY_LEN, &global_key_id); //lalalalalalalalla cahnge from&key_id
// 	//  if (ret != PSA_SUCCESS) {
// 	// 	 err = -EIO;
// 	// 	 LOG_ERR("Failed to import the private key for key agreement %d", ret);
// 	// 	 goto exit;
// 	//  }
// 	 // Performing Key Agreement (ECDH)
 
	 
// 	 // What Happens Here?
 
// 	 // Your device and another device exchange public keys.
// 	 // Using your private key and the other party's public key, you compute the shared secret (DH Key).
 
 
// 	 memcpy(&tmp_pub_key_buf[1], ecc.public_key_be, BT_PUB_KEY_LEN);
 
 
// 	 // psa_raw_key_agreement: This function performs the ECDH key agreement. It uses the private key (key_id) and the other party's public key (tmp_pub_key_buf) to derive the shared secret key, which is then stored in ecc.dhkey_be.
	 
// 	 ret = psa_raw_key_agreement(PSA_ALG_ECDH, global_key_id, tmp_pub_key_buf, sizeof(tmp_pub_key_buf), //lalalalalla replace key-id
// 					 ecc.dhkey_be, BT_DH_KEY_LEN, &tmp_len);
// 	 if (ret != PSA_SUCCESS) {
// 		 err = -EIO;
// 		 LOG_ERR("Raw key agreement failed %d", ret);
// 		 goto exit;
// 	 }
	
 
 
// 	//  ret = psa_destroy_key(key_id);
// 	//  if (ret != PSA_SUCCESS) {
// 	// 	 LOG_ERR("Failed to destroy the key %d", ret);
// 	// 	 err = -EIO;
// 	// 	 goto exit;
// 	//  }
	
// 	//uncomment this

// 	//  LOG_INF("ECC Private Key for nrf5340 (debugging only): ");
// 	//  LOG_HEXDUMP_INF(ecc.private_key_be, BT_PRIV_KEY_LEN, "Private Key");
	 
	 
// 	//  LOG_HEXDUMP_INF(tmp_pub_key_buf, BT_PUB_KEY_LEN, "REMOTEE Public Key from key arrangement step");//jasmine
// 	//uncomment this
// 	 err = 0;
 
//  exit:
// 	 /* Change to cooperative priority while we do the callback */
// 	 k_sched_lock();
 
// 	 if (dh_key_cb) {
// 		 bt_dh_key_cb_t cb = dh_key_cb;
 
// 		 dh_key_cb = NULL;
// 		 atomic_clear_bit(flags, PENDING_DHKEY);
 
// 		 if (err) {
// 			 cb(NULL);
// 		 } else {
// 			 uint8_t dhkey[BT_DH_KEY_LEN];
 
// 			 sys_memcpy_swap(dhkey, ecc.dhkey_be, sizeof(ecc.dhkey_be));
// 			 LOG_INF("DERIVED DH KEY");
// 			 LOG_HEXDUMP_INF(dhkey, BT_DH_KEY_LEN, "DH Key");
// 			 cb(dhkey);
 
// 		 }
// 	 }
 
// 	 k_sched_unlock();
//  }
 
//  int bt_pub_key_gen(struct bt_pub_key_cb *new_cb){
// 	LOG_INF("JASMIN: bt_pub_key_gen called");
// 	 struct bt_pub_key_cb *cb;
 
// 	 if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
// 		LOG_INF("Using debug keys - skipping regular key generation");
// 		 atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);
// 		 __ASSERT_NO_MSG(new_cb->func != NULL);

		 
// 		 new_cb->func(debug_public_key);
// 		 return 0;
// 	 }
 
// 	 if (!new_cb) {
// 		 return -EINVAL;
// 	 }
 
// 	 SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
// 		 if (cb == new_cb) {
// 			 LOG_WRN("Callback already registered");
// 			 return -EALREADY;
// 		 }
// 	 }
 
// 	 if (atomic_test_bit(flags, PENDING_DHKEY)) {
// 		 LOG_WRN("Busy performing another ECDH operation");
// 		 return -EBUSY;
// 	 }
 
// 	 sys_slist_prepend(&pub_key_cb_slist, &new_cb->node);
 
// 	 if (atomic_test_and_set_bit(flags, PENDING_PUB_KEY)) {
// 		 return 0;
// 	 }
 
// 	 atomic_clear_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);
	 
 
// 	 LOG_INF("JASMIN: putting pub_key worker in the queue");
	
// 	 if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
// 		 bt_long_wq_submit(&pub_key_work);
// 		 LOG_INF("Submitting to long WQ: %d", IS_ENABLED(CONFIG_BT_LONG_WQ));

// 	 } else {
// 		 k_work_submit(&pub_key_work);
	 
// 	}
// 	LOG_INF("After submit to WQ");
// 	// test_secure_pubkey();

	
 
 
// 	 return 0;
//  }

//    //keygen




// void bt_use_secure_pub_key(void)
// {
//     uint8_t secure_pub[BT_PUB_KEY_LEN];
//     size_t actual_len = 0;

//     psa_status_t status = dp_ble_keygen(secure_pub, sizeof(secure_pub), &actual_len);
//     if (status == PSA_SUCCESS) {
//         LOG_HEXDUMP_INF(secure_pub, BT_PUB_KEY_LEN, "Secure Public Key from Partition");
//         // Now you can use `secure_pub` in your ECC operations if needed
//     } else {
//         LOG_ERR("Failed to get Secure Public Key from Partition: %d", status);
//     }
// }




// //keygem
	 
 
//  void bt_pub_key_hci_disrupted(void)
//  {
// 	 struct bt_pub_key_cb *cb;
 
// 	 atomic_clear_bit(flags, PENDING_PUB_KEY);
 
// 	 SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
// 		 if (cb->func) {
// 			 cb->func(NULL);
// 		 }
// 	 }
 
// 	 sys_slist_init(&pub_key_cb_slist);
//  }


// //keygen




// //keygen










 
//  const uint8_t *bt_pub_key_get(void)
//  {
// 	 if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
// 		LOG_INF("Using Debug Public Key"); //jasmine-mobile-debug
// 		LOG_HEXDUMP_INF(debug_public_key, BT_PUB_KEY_LEN, "Debug Public Key: ");
// 		 return debug_public_key;
// 	 }
 
// 	 if (atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
// 		LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "NRFFFFFFFFFFFFF Public Key: ");

		
// 		 return pub_key;
// 	 }
 
// 	 return NULL;
//  }
 
//  int bt_dh_key_gen(const uint8_t remote_pk[BT_PUB_KEY_LEN], bt_dh_key_cb_t cb)
//  {
// 	 if (dh_key_cb == cb) {
// 		 return -EALREADY;
// 	 }
 
// 	 if (!atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
// 		 return -EADDRNOTAVAIL;
// 	 }
 
// 	 if (dh_key_cb ||
// 		 atomic_test_bit(flags, PENDING_PUB_KEY) ||
// 		 atomic_test_and_set_bit(flags, PENDING_DHKEY)) {
// 		 return -EBUSY;
// 	 }
 
// 	 dh_key_cb = cb;



// ///////////////////////////////////////////////
// 	//   Log whether the device is using debug keys or the generated public key
// 	//   if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
//     //     LOG_INF("Using Debug Keys for DH Key Generation");
//     //     LOG_HEXDUMP_INF(debug_public_key, BT_PUB_KEY_LEN, "Debug Public Key: ");
//     // } else {
//     //     LOG_INF("Using Generated Mobile Device Public Key for DH Key Generation");
//     //     LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "Mobile Public Key: ");
// 	// 	//////////////////////////////////////////////////////////
//     // }

 
// 	 /* Convert X and Y coordinates from little-endian to
// 	  * big-endian (expected by the crypto API).
// 	  */
// 	 sys_memcpy_swap(ecc.public_key_be, remote_pk, BT_PUB_KEY_COORD_LEN);
// 	 sys_memcpy_swap(&ecc.public_key_be[BT_PUB_KEY_COORD_LEN],
// 			 &remote_pk[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);
 
// 	 if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
// 		 bt_long_wq_submit(&dh_key_work);
// 	 } else {
// 		 k_work_submit(&dh_key_work);
		
// 	 }
 
// 	 return 0;
//  }
// //Kkeygen


// //keygen
 
//  #ifdef ZTEST_UNITTEST
//  uint8_t const *bt_ecc_get_public_key(void)
//  {
// 	 return pub_key;
//  }
 
//  uint8_t const *bt_ecc_get_internal_debug_public_key(void)
//  {
// 	 return debug_public_key;
//  }
 
//  sys_slist_t *bt_ecc_get_pub_key_cb_slist(void)
//  {
// 	 return &pub_key_cb_slist;
//  }
 
//  bt_dh_key_cb_t *bt_ecc_get_dh_key_cb(void)
//  {
// 	 return &dh_key_cb;
//  }
//  #endif /* ZTEST_UNITTEST */
 
 
 // Step 1: Initialization
 
 //     The board initializes Bluetooth communication. It sets up internal flags and prepares for public key generation and Diffie-Hellman key exchange.
 //     At this point, the system is either in "debug" mode (where pre-set keys are used) or normal mode, where it generates the actual keys. For the purpose of Bluetooth communication, the board is ready to generate and exchange public keys for secure communication.
 
 // Step 2: Request for Public Key Generation (bt_pub_key_gen)
 
 //     When your phone (or any Bluetooth device) connects to the board, the board needs to generate a public key.
 //     The board calls bt_pub_key_gen to generate a public key. This function will:
 //         Check if public key generation is already in progress. If it is, it won’t start another operation.
 //         Register a callback function (new_cb) that will be called once the public key is ready.
 //         If the board is in "debug" mode, it will use a predefined public key (debug_public_key) instead of generating a new one.
 
 // Step 3: Bluetooth Key Exchange Preparation
 
 //     If the board is not in debug mode and the public key isn’t already available, it submits a work item (pub_key_work) to generate the public key asynchronously.
 //         This work item will eventually call a background function to generate the public key and make it available.
 
 // Step 4: Bluetooth Public Key Availability
 
 //     The board waits for the public key to be generated. Once the public key is ready, it is sent back to the phone using the callback function provided by the phone.
 //     If everything goes well, the phone receives the public key and proceeds to exchange the key securely.
 
 // Step 5: Diffie-Hellman (DH) Key Generation (bt_dh_key_gen)
 
 //     Once the phone has the board’s public key, it wants to compute a shared secret key to secure the communication.
 //     The phone sends its public key to the board. This is where the Diffie-Hellman key exchange comes into play.
 //     The board takes the remote public key (the phone’s public key), and the board’s own private key, and uses these to perform Diffie-Hellman key agreement.
 
 // Step 6: Key Agreement and Shared Secret Computation
 
 //     The board receives the phone’s public key and uses its private key (ecc.private_key_be) along with the phone’s public key (ecc.public_key_be) to compute a shared secret. This is done using the psa_raw_key_agreement() function.
 //         The result of this computation is the Diffie-Hellman shared secret key (ecc.dhkey_be).
 //     Once the shared secret is derived, the board will call the callback (dh_key_cb) that was previously set in bt_dh_key_gen. This callback will either:
 //         Provide the shared key (dhkey).
 //         Handle any errors if something goes wrong (for example, key agreement failure).
 
 // Step 7: Key Exchange Completion
 
 //     Once the Diffie-Hellman computation is complete, the board will:
 //         Log the shared secret (for debugging purposes, it might log the hex representation of the derived DH key).
 //         Return the derived key to the phone through the callback function, allowing the phone to establish a secure connection using the shared secret.
 
 // Step 8: Cleanup
 
 //     After the Diffie-Hellman computation, the board cleans up by destroying the private key (psa_destroy_key()). This ensures that the sensitive key material is cleared from memory.
 
 // Step 9: Key Use
 
 //     With both the phone and the board having the same shared secret (the Diffie-Hellman key), they can now use this shared key to encrypt and decrypt communication between them, ensuring a secure communication channel.
 
 // Summary of the Flow
 
 //     Bluetooth Connection: Your phone connects to the board via Bluetooth.
 //     Public Key Generation: The board generates or retrieves its public key.
 //     Exchange of Public Keys: The phone sends its public key to the board, and the board receives it.
 //     Diffie-Hellman Key Agreement: Using its private key and the phone’s public key, the board computes a shared secret (Diffie-Hellman key).
 //     Callback Handling: The shared secret is passed to the phone via the callback, and secure communication can now take place.
 //     Key Destruction: Once the key exchange is complete, the board destroys the keys for security.




















// #include <stdint.h>
// #include <zephyr/sys/byteorder.h>
// #include <zephyr/sys/check.h>
// #include <zephyr/bluetooth/hci.h>
// #include <psa/crypto.h>
// #include "long_wq.h"
// #include "ecc.h"
// #include "hci_core.h"
// #include "/home/jasmine/zephyrproject/zephyr/samples/bluetooth/peripheral_sc_only/src/BLE_partition.h"

// #define TFN_PUBKEY_EXPORT_LEN 65  // Should match the secure partition




// #define LOG_LEVEL CONFIG_BT_HCI_CORE_LOG_LEVEL
// #include <zephyr/logging/log.h>
// LOG_MODULE_REGISTER(bt_ecc);

// static uint8_t pub_key[BT_PUB_KEY_LEN];
// static sys_slist_t pub_key_cb_slist;
// static bt_dh_key_cb_t dh_key_cb;
// static psa_key_id_t sec_key_id; // handle for secure private key


// static void generate_pub_key(struct k_work *work);
// static void generate_dh_key(struct k_work *work);
// K_WORK_DEFINE(pub_key_work, generate_pub_key);
// K_WORK_DEFINE(dh_key_work, generate_dh_key);

// enum {
//     PENDING_PUB_KEY,
//     PENDING_DHKEY,
//     NUM_FLAGS,
// };

// static ATOMIC_DEFINE(flags, NUM_FLAGS);

// static struct {
//     uint8_t private_key_be[BT_PRIV_KEY_LEN];

//     union {
//         uint8_t public_key_be[BT_PUB_KEY_LEN];
//         uint8_t dhkey_be[BT_DH_KEY_LEN];
//     };
// } ecc;

// static psa_key_id_t global_key_id;
// psa_key_id_t my_key_id;

// static const uint8_t debug_private_key_be[BT_PRIV_KEY_LEN] = {
//     0x3f, 0x49, 0xf6, 0xd4, 0xa3, 0xc5, 0x5f, 0x38,
//     0x74, 0xc9, 0xb3, 0xe3, 0xd2, 0x10, 0x3f, 0x50,
//     0x4a, 0xff, 0x60, 0x7b, 0xeb, 0x40, 0xb7, 0x99,
//     0x58, 0x99, 0xb8, 0xa6, 0xcd, 0x3c, 0x1a, 0xbd,
// };

// static const uint8_t debug_public_key[BT_PUB_KEY_LEN] = {
//     /* X */
//     0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc,
//     0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91, 0xf4, 0xef,
//     0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e,
//     0x2c, 0xbe, 0x97, 0xf2, 0xd2, 0x03, 0xb0, 0x20,
//     /* Y */
//     0x8b, 0xd2, 0x89, 0x15, 0xd0, 0x8e, 0x1c, 0x74,
//     0x24, 0x30, 0xed, 0x8f, 0xc2, 0x45, 0x63, 0x76,
//     0x5c, 0x15, 0x52, 0x5a, 0xbf, 0x9a, 0x32, 0x63,
//     0x6d, 0xeb, 0x2a, 0x65, 0x49, 0x9c, 0x80, 0xdc
// };

// bool bt_pub_key_is_debug(uint8_t *cmp_pub_key)
// {
//     return memcmp(cmp_pub_key, debug_public_key, BT_PUB_KEY_LEN) == 0;
// }

// bool bt_pub_key_is_valid(const uint8_t key[BT_PUB_KEY_LEN])
// {
//     uint8_t key_be[BT_PUB_KEY_LEN + 1];
//     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
//     psa_status_t ret;
//     psa_key_id_t handle;

//     psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
//     psa_set_key_bits(&attr, 256);
//     psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
//     psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

//     key_be[0] = 0x04;
//     sys_memcpy_swap(&key_be[1], key, BT_PUB_KEY_COORD_LEN);
//     sys_memcpy_swap(&key_be[1 + BT_PUB_KEY_COORD_LEN], &key[BT_PUB_KEY_COORD_LEN],
//             BT_PUB_KEY_COORD_LEN);

//     ret = psa_import_key(&attr, key_be, sizeof(key_be), &handle);
//     psa_reset_key_attributes(&attr);

//     if (ret == PSA_SUCCESS) {
//         psa_destroy_key(handle);
//         return true;
//     }

//     return false;
// }

// static void set_key_attributes(psa_key_attributes_t *attr)
// {
//     psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
//     psa_set_key_bits(attr, 256);
// #ifdef CONFIG_JASMIN_CHANGE
//     psa_set_key_usage_flags(attr, PSA_KEY_USAGE_DERIVE);
// #else
//     psa_set_key_usage_flags(attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
// #endif
//     psa_set_key_algorithm(attr, PSA_ALG_ECDH);
// }
// void bt_use_secure_pub_key(void)
// {
//     /* Buffer must be large enough for key_id + exported public key bytes */
//     uint8_t buf[sizeof(psa_key_id_t) + TFN_PUBKEY_EXPORT_LEN];
//     size_t pubkey_len = 0;
//     psa_status_t status;

//     status = dp_ble_keygen(buf, sizeof(buf), &pubkey_len);
//     if (status != PSA_SUCCESS) {
//         LOG_ERR("Failed to get Secure Public Key from Partition: %d", status);
//         return;
//     }

//     /* Check that returned buffer contains key_id + pubkey */
//     if (pubkey_len == 0 || (sizeof(psa_key_id_t) + pubkey_len) > sizeof(buf)) {
//         LOG_ERR("Invalid length returned from secure partition");
//         return;
//     }

//     /* Extract key_id (first bytes) */
//     psa_key_id_t returned_key_id;
//     memcpy(&returned_key_id, buf, sizeof(returned_key_id));

//     /* Extract public key bytes (following key_id). pubkey_len is length of pubkey */
//     uint8_t *pubkey_ptr = &buf[sizeof(returned_key_id)];

//     /* Save key id for later (non-secure just stores the number) */
//     global_key_id = returned_key_id;

//     /* Copy public key into local data structure and public buffer */
//     if (pubkey_len >= BT_PUB_KEY_LEN) {
//         memcpy(ecc.public_key_be, pubkey_ptr, BT_PUB_KEY_LEN);
//         memcpy(pub_key, pubkey_ptr, BT_PUB_KEY_LEN);
//         atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

//         LOG_INF("Got BLE secure public key (len=%zu), key_id=%u", pubkey_len, (unsigned)returned_key_id);
//         LOG_HEXDUMP_INF(pubkey_ptr, pubkey_len, "Secure Public Key");
//     } else {
//         LOG_ERR("Secure public key length too small: %zu", pubkey_len);
//     }
// }


// static void generate_pub_key(struct k_work *work)
// {
//     LOG_INF("generate_pub_key() was triggered");

//     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
//     struct bt_pub_key_cb *cb;
//     psa_key_id_t key_id;
//     uint8_t tmp_pub_key_buf[BT_PUB_KEY_LEN + 1];
//     size_t tmp_len;
//     int err;
//     psa_status_t ret;

//     set_key_attributes(&attr);

//     ret = psa_generate_key(&attr, &global_key_id);

//     LOG_INF("psa_generate_key() returned: %d", ret);

//     if (ret != PSA_SUCCESS) {
//         LOG_ERR("Failed to generate ECC key %d", ret);
//         err = BT_HCI_ERR_UNSPECIFIED;
//         goto done;
//     }

//     ret = psa_export_public_key(global_key_id, tmp_pub_key_buf, sizeof(tmp_pub_key_buf), &tmp_len);
//     LOG_INF("psa_export_public_key() returned: %d", ret);
//     if (ret != PSA_SUCCESS) {
//         LOG_ERR("Failed to export ECC public key %d", ret);
//         err = BT_HCI_ERR_UNSPECIFIED;
//         goto done;
//     }

//     memcpy(ecc.public_key_be, &tmp_pub_key_buf[1], BT_PUB_KEY_LEN);
//     LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "local Public Key");
// 	bt_use_secure_pub_key();

	


//     sys_memcpy_swap(pub_key, ecc.public_key_be, BT_PUB_KEY_COORD_LEN);
//     sys_memcpy_swap(&pub_key[BT_PUB_KEY_COORD_LEN],
//             &ecc.public_key_be[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);

//     atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);
//     err = 0;

// done:
//     atomic_clear_bit(flags, PENDING_PUB_KEY);

//     k_sched_lock();

//     SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
//         if (cb->func) {
//             cb->func(err ? NULL : pub_key);
//         }
//     }

//     sys_slist_init(&pub_key_cb_slist);

//     k_sched_unlock();
// }

// static void generate_dh_key(struct k_work *work)
// {
//     int err;
//     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
//     psa_status_t ret;

//     uint8_t tmp_pub_key_buf[BT_PUB_KEY_LEN + 1] = { 0x04 };
//     size_t tmp_len;

//     set_key_attributes(&attr);

//     const uint8_t *priv_key = (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS) ?
//                     debug_private_key_be :
//                     ecc.private_key_be);

//     memcpy(&tmp_pub_key_buf[1], ecc.public_key_be, BT_PUB_KEY_LEN);

//     ret = psa_raw_key_agreement(PSA_ALG_ECDH, global_key_id, tmp_pub_key_buf, sizeof(tmp_pub_key_buf),
//                     ecc.dhkey_be, BT_DH_KEY_LEN, &tmp_len);
//     if (ret != PSA_SUCCESS) {
//         err = -EIO;
//         LOG_ERR("Raw key agreement failed %d", ret);
//         goto exit;
//     }

//     err = 0;

// exit:
//     k_sched_lock();

//     if (dh_key_cb) {
//         bt_dh_key_cb_t cb = dh_key_cb;
//         dh_key_cb = NULL;
//         atomic_clear_bit(flags, PENDING_DHKEY);

//         if (err) {
//             cb(NULL);
//         } else {
//             uint8_t dhkey[BT_DH_KEY_LEN];
//             sys_memcpy_swap(dhkey, ecc.dhkey_be, sizeof(ecc.dhkey_be));
//             LOG_HEXDUMP_INF(dhkey, BT_DH_KEY_LEN, "DH Key");
//             cb(dhkey);
//         }
//     }

//     k_sched_unlock();
// }

// int bt_pub_key_gen(struct bt_pub_key_cb *new_cb){
//     LOG_INF("JASMIN: bt_pub_key_gen called");
//     struct bt_pub_key_cb *cb;

//     if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
//         LOG_INF("Using debug keys - skipping regular key generation");
//         atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);
//         __ASSERT_NO_MSG(new_cb->func != NULL);
//         new_cb->func(debug_public_key);
//         return 0;
//     }

//     if (!new_cb) {
//         return -EINVAL;
//     }

//     SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
//         if (cb == new_cb) {
//             LOG_WRN("Callback already registered");
//             return -EALREADY;
//         }
//     }

//     if (atomic_test_bit(flags, PENDING_DHKEY)) {
//         LOG_WRN("Busy performing another ECDH operation");
//         return -EBUSY;
//     }

//     sys_slist_prepend(&pub_key_cb_slist, &new_cb->node);

//     if (atomic_test_and_set_bit(flags, PENDING_PUB_KEY)) {
//         return 0;
//     }

//     atomic_clear_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

//     LOG_INF("JASMIN: putting pub_key worker in the queue");

//     if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
//         bt_long_wq_submit(&pub_key_work);
//         LOG_INF("Submitting to long WQ: %d", IS_ENABLED(CONFIG_BT_LONG_WQ));
//     } else {
//         k_work_submit(&pub_key_work);
//     }

//     LOG_INF("After submit to WQ");

//     // Trigger secure partition key generation here
//     bt_use_secure_pub_key();

//     return 0;
// }



// void bt_pub_key_hci_disrupted(void)
// {
//     struct bt_pub_key_cb *cb;

//     atomic_clear_bit(flags, PENDING_PUB_KEY);

//     SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
//         if (cb->func) {
//             cb->func(NULL);
//         }
//     }

//     sys_slist_init(&pub_key_cb_slist);
// }

// const uint8_t *bt_pub_key_get(void)
// {
//     if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
//         LOG_INF("Using Debug Public Key");
//         LOG_HEXDUMP_INF(debug_public_key, BT_PUB_KEY_LEN, "Debug Public Key: ");
//         return debug_public_key;
//     }

//     if (atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
//         LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "Local Public Key: ");
//         return pub_key;
//     }

//     return NULL;
// }

// int bt_dh_key_gen(const uint8_t remote_pk[BT_PUB_KEY_LEN], bt_dh_key_cb_t cb)
// {
//     if (dh_key_cb == cb) {
//         return -EALREADY;
//     }

//     if (!atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
//         return -EADDRNOTAVAIL;
//     }

//     if (dh_key_cb ||
//         atomic_test_bit(flags, PENDING_PUB_KEY) ||
//         atomic_test_and_set_bit(flags, PENDING_DHKEY)) {
//         return -EBUSY;
//     }

//     dh_key_cb = cb;

//     sys_memcpy_swap(ecc.public_key_be, remote_pk, BT_PUB_KEY_COORD_LEN);
//     sys_memcpy_swap(&ecc.public_key_be[BT_PUB_KEY_COORD_LEN],
//             &remote_pk[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);

//     if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
//         bt_long_wq_submit(&dh_key_work);
//     } else {
//         k_work_submit(&dh_key_work);
//     }

//     return 0;
// }

// #ifdef ZTEST_UNITTEST
// uint8_t const *bt_ecc_get_public_key(void)
// {
//     return pub_key;
// }

// uint8_t const *bt_ecc_get_internal_debug_public_key(void)
// {
//     return debug_public_key;
// }

// sys_slist_t *bt_ecc_get_pub_key_cb_slist(void)
// {
//     return &pub_key_cb_slist;
// }

// bt_dh_key_cb_t *bt_ecc_get_dh_key_cb(void)
// {
//     return &dh_key_cb;
// }
// #endif


















// #include <stdbool.h>
// #include <zephyr/sys/byteorder.h>
// #include <zephyr/sys/check.h>
// #include <zephyr/bluetooth/hci.h>
// #include <psa/crypto.h>
// #include "long_wq.h"
// #include "ecc.h"

// #include "hci_core.h"
// #include "/home/jasmine/zephyrproject/zephyr/samples/bluetooth/peripheral_sc_only/src/BLE_partition.h"

// #define TFN_PUBKEY_EXPORT_LEN 65  // Should match the secure partition

// #define LOG_LEVEL CONFIG_BT_HCI_CORE_LOG_LEVEL
// #include <zephyr/logging/log.h>
// LOG_MODULE_REGISTER(bt_ecc);

// static uint8_t pub_key[BT_PUB_KEY_LEN];
// static sys_slist_t pub_key_cb_slist;
// static bt_dh_key_cb_t dh_key_cb;
// static psa_key_id_t global_key_id; // handle for secure private key

// static void generate_pub_key(struct k_work *work);
// static void generate_dh_key(struct k_work *work);
// K_WORK_DEFINE(pub_key_work, generate_pub_key);
// K_WORK_DEFINE(dh_key_work, generate_dh_key);

// enum {
//     PENDING_PUB_KEY,
//     PENDING_DHKEY,
//     NUM_FLAGS,
// };

// static ATOMIC_DEFINE(flags, NUM_FLAGS);

// static struct {
//     uint8_t private_key_be[BT_PRIV_KEY_LEN];

//     union {
//         uint8_t public_key_be[BT_PUB_KEY_LEN];
//         uint8_t dhkey_be[BT_DH_KEY_LEN];
//     };
// } ecc;

// static const uint8_t debug_private_key_be[BT_PRIV_KEY_LEN] = {
//     0x3f, 0x49, 0xf6, 0xd4, 0xa3, 0xc5, 0x5f, 0x38,
//     0x74, 0xc9, 0xb3, 0xe3, 0xd2, 0x10, 0x3f, 0x50,
//     0x4a, 0xff, 0x60, 0x7b, 0xeb, 0x40, 0xb7, 0x99,
//     0x58, 0x99, 0xb8, 0xa6, 0xcd, 0x3c, 0x1a, 0xbd,
// };

// static const uint8_t debug_public_key[BT_PUB_KEY_LEN] = {
//     /* X */
//     0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc,
//     0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91, 0xf4, 0xef,
//     0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e,
//     0x2c, 0xbe, 0x97, 0xf2, 0xd2, 0x03, 0xb0, 0x20,
//     /* Y */
//     0x8b, 0xd2, 0x89, 0x15, 0xd0, 0x8e, 0x1c, 0x74,
//     0x24, 0x30, 0xed, 0x8f, 0xc2, 0x45, 0x63, 0x76,
//     0x5c, 0x15, 0x52, 0x5a, 0xbf, 0x9a, 0x32, 0x63,
//     0x6d, 0xeb, 0x2a, 0x65, 0x49, 0x9c, 0x80, 0xdc
// };

// bool bt_pub_key_is_debug(uint8_t *cmp_pub_key)
// {
//     return memcmp(cmp_pub_key, debug_public_key, BT_PUB_KEY_LEN) == 0;
// }

// bool bt_pub_key_is_valid(const uint8_t key[BT_PUB_KEY_LEN])
// {
//     uint8_t key_be[BT_PUB_KEY_LEN + 1];
//     psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
//     psa_status_t ret;
//     psa_key_id_t handle;

//     psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
//     psa_set_key_bits(&attr, 256);
//     psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
//     psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

//     key_be[0] = 0x04;
//     sys_memcpy_swap(&key_be[1], key, BT_PUB_KEY_COORD_LEN);
//     sys_memcpy_swap(&key_be[1 + BT_PUB_KEY_COORD_LEN], &key[BT_PUB_KEY_COORD_LEN],
//             BT_PUB_KEY_COORD_LEN);

//     ret = psa_import_key(&attr, key_be, sizeof(key_be), &handle);
//     psa_reset_key_attributes(&attr);

//     if (ret == PSA_SUCCESS) {
//         psa_destroy_key(handle);
//         return true;
//     }

//     return false;
// }

// void bt_use_secure_pub_key(void)
// {
//     uint8_t buf[sizeof(psa_key_id_t) + TFN_PUBKEY_EXPORT_LEN];
//     size_t pubkey_len = 0;
//     psa_status_t status;

//     status = dp_ble_keygen(buf, sizeof(buf), &pubkey_len);
//     if (status != PSA_SUCCESS) {
//         LOG_ERR("Failed to get Secure Public Key from Partition: %d", status);
//         return;
//     }

//     if (pubkey_len == 0 || (sizeof(psa_key_id_t) + pubkey_len) > sizeof(buf)) {
//         LOG_ERR("Invalid length returned from secure partition");
//         return;
//     }

//     psa_key_id_t returned_key_id;
//     memcpy(&returned_key_id, buf, sizeof(returned_key_id));
//     global_key_id = returned_key_id;

//     // uint8_t *pubkey_ptr = &buf[sizeof(returned_key_id)];

//     // if (pubkey_len >= BT_PUB_KEY_LEN) {
//     //     memcpy(ecc.public_key_be, pubkey_ptr, BT_PUB_KEY_LEN);
//     //     memcpy(pub_key, pubkey_ptr, BT_PUB_KEY_LEN);
//     //     atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

//     //     LOG_INF("Got BLE secure public key (len=%zu), key_id=%u", pubkey_len, (unsigned)returned_key_id);
//     //     LOG_HEXDUMP_INF(pubkey_ptr, pubkey_len, "Secure Public Key");
//     // } else {
//     //     LOG_ERR("Secure public key length too small: %zu", pubkey_len);
//     // }
//         uint8_t *pubkey_ptr = &buf[sizeof(returned_key_id)];

//     /* psa_export_public_key returns 0x04 || X || Y -> total TFN_PUBKEY_EXPORT_LEN (65) */
//     if (pubkey_len == TFN_PUBKEY_EXPORT_LEN) {
//         /* Skip the leading 0x04 marker */
//         memcpy(ecc.public_key_be, pubkey_ptr + 1, BT_PUB_KEY_LEN);   /* copy 64 bytes X||Y */
//         /* Copy to public buffer as little-endian swapped coordinates for Zephyr */
//         memcpy(pub_key, pubkey_ptr + 1, BT_PUB_KEY_LEN);
//         atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

//         LOG_INF("Got BLE secure public key (len=%zu), key_id=%u", pubkey_len, (unsigned)returned_key_id);
//         LOG_HEXDUMP_INF(pubkey_ptr + 1, BT_PUB_KEY_LEN, "Secure Public Key (X||Y)");
//     } else {
//         LOG_ERR("Secure public key length unexpected: %zu", pubkey_len);
//     }

// }

// static void generate_pub_key(struct k_work *work)
// {
//     LOG_INF("generate_pub_key() triggered");

//     int err = 0;
//     struct bt_pub_key_cb *cb;

//     // Fetch secure public key
//     bt_use_secure_pub_key();

//     // Swap coordinates to internal format
//     sys_memcpy_swap(pub_key, ecc.public_key_be, BT_PUB_KEY_COORD_LEN);
//     sys_memcpy_swap(&pub_key[BT_PUB_KEY_COORD_LEN],
//             &ecc.public_key_be[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);

//     atomic_clear_bit(flags, PENDING_PUB_KEY);

//     k_sched_lock();
//     SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
//         if (cb->func) {
//             cb->func(err ? NULL : pub_key);
//         }
//     }
//     sys_slist_init(&pub_key_cb_slist);
//     k_sched_unlock();
// }

// static void generate_dh_key(struct k_work *work)
// {
//     int err = 0;
//     // uint8_t dhkey[BT_DH_KEY_LEN] = {0};

//     // // Call secure partition wrapper for ECDH
//     // psa_status_t status = dp_ble_ecdh(ecc.public_key_be, dhkey, sizeof(dhkey));

 

//     // Allocate buffer for the shared secret (32 bytes for P-256)
//     uint8_t dhkey[TFN_ECDH_SHARED_KEY_LEN];

//     // Prepare remote public key in uncompressed format
//     uint8_t tmp_pub_key_buf[TFN_PUBKEY_EXPORT_LEN];
//     tmp_pub_key_buf[0] = 0x04;
//     memcpy(&tmp_pub_key_buf[1], ecc.public_key_be, BT_PUB_KEY_LEN);

//     // Call secure partition wrapper for ECDH
//     psa_status_t status = dp_ble_ecdh(tmp_pub_key_buf, dhkey, sizeof(dhkey));

//     if (status != PSA_SUCCESS) {
//         err = -EIO;
//         LOG_ERR("Secure ECDH failed: %d", status);
//     } else {
//         LOG_HEXDUMP_INF(dhkey, TFN_ECDH_SHARED_KEY_LEN, "DH Key");
//     }


//     // Callback to Bluetooth stack
//     k_sched_lock();
//     if (dh_key_cb) {
//         bt_dh_key_cb_t cb = dh_key_cb;
//         dh_key_cb = NULL;
//         atomic_clear_bit(flags, PENDING_DHKEY);

//         if (err) {
//             cb(NULL);
//         } else {
//             cb(dhkey);
//         }
//     }
//     k_sched_unlock();
// }


// int bt_pub_key_gen(struct bt_pub_key_cb *new_cb)
// {
//     LOG_INF("bt_pub_key_gen called");

//     struct bt_pub_key_cb *cb;

//     if (!new_cb) {
//         return -EINVAL;
//     }

//     SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
//         if (cb == new_cb) {
//             LOG_WRN("Callback already registered");
//             return -EALREADY;
//         }
//     }

//     if (atomic_test_bit(flags, PENDING_DHKEY)) {
//         LOG_WRN("Busy performing another ECDH operation");
//         return -EBUSY;
//     }

//     sys_slist_prepend(&pub_key_cb_slist, &new_cb->node);

//     if (atomic_test_and_set_bit(flags, PENDING_PUB_KEY)) {
//         return 0;
//     }

//     atomic_clear_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

//     if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
//         bt_long_wq_submit(&pub_key_work);
//     } else {
//         k_work_submit(&pub_key_work);
//     }

//     return 0;
// }

// void bt_pub_key_hci_disrupted(void)
// {
//     struct bt_pub_key_cb *cb;

//     atomic_clear_bit(flags, PENDING_PUB_KEY);

//     SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
//         if (cb->func) {
//             cb->func(NULL);
//         }
//     }

//     sys_slist_init(&pub_key_cb_slist);
// }

// const uint8_t *bt_pub_key_get(void)
// {
//     // Only return debug key if CONFIG_BT_USE_DEBUG_KEYS is enabled
//     if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
//         LOG_INF("Using Debug Public Key");
//         LOG_HEXDUMP_INF(debug_public_key, BT_PUB_KEY_LEN, "Debug Public Key: ");
//         return debug_public_key;
//     }

//     if (atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
//         LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "Local Public Key: ");
//         return pub_key;
//     }

//     return NULL;
// }

// int bt_dh_key_gen(const uint8_t remote_pk[BT_PUB_KEY_LEN], bt_dh_key_cb_t cb)
// {
//     if (dh_key_cb == cb) {
//         return -EALREADY;
//     }

//     if (!atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
//         return -EADDRNOTAVAIL;
//     }

//     if (dh_key_cb ||
//         atomic_test_bit(flags, PENDING_PUB_KEY) ||
//         atomic_test_and_set_bit(flags, PENDING_DHKEY)) {
//         return -EBUSY;
//     }

//     dh_key_cb = cb;

//     sys_memcpy_swap(ecc.public_key_be, remote_pk, BT_PUB_KEY_COORD_LEN);
//     sys_memcpy_swap(&ecc.public_key_be[BT_PUB_KEY_COORD_LEN],
//             &remote_pk[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);

//     if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
//         bt_long_wq_submit(&dh_key_work);
//     } else {
//         k_work_submit(&dh_key_work);
//     }

//     return 0;
// }








#include <stdbool.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/check.h>
#include <zephyr/bluetooth/hci.h>
#include <psa/crypto.h>
#include "long_wq.h"
#include "ecc.h"

#include "hci_core.h"
#include "/home/jasmine/zephyrproject/zephyr/samples/bluetooth/peripheral_sc_only/src/BLE_partition.h"

#define TFN_PUBKEY_EXPORT_LEN 65  // Should match the secure partition

#define LOG_LEVEL CONFIG_BT_HCI_CORE_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(bt_ecc);

static uint8_t pub_key[BT_PUB_KEY_LEN];
static sys_slist_t pub_key_cb_slist;
static bt_dh_key_cb_t dh_key_cb;
static psa_key_id_t global_key_id; // handle for secure private key
static uint8_t dh_key_cb_remote_key[BT_PUB_KEY_LEN]; // store remote public key for ECDH
static psa_key_id_t current_private_key_id = 0; // 0 = not initialized

static void generate_pub_key(struct k_work *work);
static void generate_dh_key(struct k_work *work);
K_WORK_DEFINE(pub_key_work, generate_pub_key);
K_WORK_DEFINE(dh_key_work, generate_dh_key);

enum {
    PENDING_PUB_KEY,
    PENDING_DHKEY,
    NUM_FLAGS,
};

static ATOMIC_DEFINE(flags, NUM_FLAGS);

static struct {
    uint8_t private_key_be[BT_PRIV_KEY_LEN];

    union {
        uint8_t public_key_be[BT_PUB_KEY_LEN];
        uint8_t dhkey_be[BT_DH_KEY_LEN];
    };
} ecc;

static const uint8_t debug_public_key[BT_PUB_KEY_LEN] = {
    /* X */
    0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc,
    0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91, 0xf4, 0xef,
    0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e,
    0x2c, 0xbe, 0x97, 0xf2, 0xd2, 0x03, 0xb0, 0x20,
    /* Y */
    0x8b, 0xd2, 0x89, 0x15, 0xd0, 0x8e, 0x1c, 0x74,
    0x24, 0x30, 0xed, 0x8f, 0xc2, 0x45, 0x63, 0x76,
    0x5c, 0x15, 0x52, 0x5a, 0xbf, 0x9a, 0x32, 0x63,
    0x6d, 0xeb, 0x2a, 0x65, 0x49, 0x9c, 0x80, 0xdc
};

bool bt_pub_key_is_debug(uint8_t *cmp_pub_key)
{
    return memcmp(cmp_pub_key, debug_public_key, BT_PUB_KEY_LEN) == 0;
}

bool bt_pub_key_is_valid(const uint8_t key[BT_PUB_KEY_LEN])
{
    uint8_t key_be[BT_PUB_KEY_LEN + 1];
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t ret;
    psa_key_id_t handle;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    key_be[0] = 0x04;
    sys_memcpy_swap(&key_be[1], key, BT_PUB_KEY_COORD_LEN);
    sys_memcpy_swap(&key_be[1 + BT_PUB_KEY_COORD_LEN], &key[BT_PUB_KEY_COORD_LEN],
            BT_PUB_KEY_COORD_LEN);

    ret = psa_import_key(&attr, key_be, sizeof(key_be), &handle);
    psa_reset_key_attributes(&attr);

    if (ret == PSA_SUCCESS) {
        psa_destroy_key(handle);
        return true;
    }

    return false;
}

//adding more than onr private key
// void bt_use_secure_pub_key(void)
// {
//     uint8_t buf[sizeof(psa_key_id_t) + TFN_PUBKEY_EXPORT_LEN];
//     size_t pubkey_len = 0;
//     psa_status_t status;

//     LOG_INF("=== SECURE KEY GENERATION STARTING ===");
//     LOG_INF("Requesting key from SECURE PARTITION (TrustZone)...");

//     status = dp_ble_keygen(buf, sizeof(buf), &pubkey_len);
//     if (status != PSA_SUCCESS) {
//         LOG_ERR("Failed to get Secure Public Key from Partition: %d", status);
//         return;
//     }

//     LOG_INF("*** SECURE KEY SUCCESSFULLY GENERATED IN TRUSTZONE ***");

//     if (pubkey_len != TFN_PUBKEY_EXPORT_LEN) {
//         LOG_ERR("Secure public key length unexpected: %zu", pubkey_len);
//         return;
//     }

//     psa_key_id_t returned_key_id;
//     memcpy(&returned_key_id, buf, sizeof(returned_key_id));
//     global_key_id = returned_key_id;

//     uint8_t *pubkey_ptr = &buf[sizeof(returned_key_id)];

//     memcpy(ecc.public_key_be, pubkey_ptr + 1, BT_PUB_KEY_LEN);   // exact X||Y in big-endian

//     // Convert public key from big-endian to little-endian for Bluetooth
//     sys_memcpy_swap(pub_key, ecc.public_key_be, BT_PUB_KEY_COORD_LEN);
//     sys_memcpy_swap(&pub_key[BT_PUB_KEY_COORD_LEN],
//             &ecc.public_key_be[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);

//     atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

//     LOG_INF("Got BLE secure public key (len=%zu), key_id=%u", pubkey_len, (unsigned)returned_key_id);
//     LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "Secure Key (Big-Endian from partition)");
//     LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "Secure Key (Little-Endian for Bluetooth)");
// }
//adding more than onr private key
void bt_use_secure_pub_key(void)
  {
      psa_key_id_t private_key_id;
      uint8_t pubkey_data[TFN_PUBKEY_EXPORT_LEN];
      size_t pubkey_len = 0;
      psa_status_t status;

      LOG_INF("=== SECURE KEY GENERATION STARTING ===");
      LOG_INF("Requesting key from SECURE PARTITION (TrustZone)...");

      status = dp_ble_keygen(&private_key_id, pubkey_data, &pubkey_len);
      if (status != PSA_SUCCESS) {
          LOG_ERR("Failed to get Secure Public Key: %d", status);
          return;
      }

      // Store private key ID for later ECDH use
      current_private_key_id = private_key_id;

      LOG_INF("*** KEY GENERATED (ID=0x%08x) IN TRUSTZONE ***", private_key_id);

      if (pubkey_len != TFN_PUBKEY_EXPORT_LEN) {
          LOG_ERR("Secure public key length unexpected: %zu", pubkey_len);
          return;
      }

      // Skip 0x04 prefix, copy X||Y (64 bytes)
      memcpy(ecc.public_key_be, pubkey_data + 1, BT_PUB_KEY_LEN);

      // Convert to little-endian for Bluetooth
      sys_memcpy_swap(pub_key, ecc.public_key_be, BT_PUB_KEY_COORD_LEN);
      sys_memcpy_swap(&pub_key[BT_PUB_KEY_COORD_LEN],
              &ecc.public_key_be[BT_PUB_KEY_COORD_LEN],
  BT_PUB_KEY_COORD_LEN);

      atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

      LOG_INF("Got BLE secure public key (ID=0x%08x)", private_key_id);
      LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "Secure Key (Big-Endian)");
      LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "Secure Key (Little-Endian for BT)");
  }
//until here  for adding more than one private key

static void generate_pub_key(struct k_work *work)
{
    LOG_INF("generate_pub_key() triggered");

    int err = 0;
    struct bt_pub_key_cb *cb;

    bt_use_secure_pub_key();

    atomic_clear_bit(flags, PENDING_PUB_KEY);

    k_sched_lock();
    SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
        if (cb->func) {
            cb->func(err ? NULL : pub_key);
        }
    }
    sys_slist_init(&pub_key_cb_slist);
    k_sched_unlock();
}

//adding more than one private key
// static void generate_dh_key(struct k_work *work)
// {
//     int err = 0;
//     uint8_t dhkey[TFN_ECDH_SHARED_KEY_LEN];

//     uint8_t tmp_pub_key_buf[TFN_PUBKEY_EXPORT_LEN];
//     tmp_pub_key_buf[0] = 0x04; // uncompressed
//     memcpy(&tmp_pub_key_buf[1], dh_key_cb_remote_key, BT_PUB_KEY_LEN); // X||Y directly

//     // LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "Local Secure Public Key (X||Y)");
//     // LOG_HEXDUMP_INF(tmp_pub_key_buf + 1, BT_PUB_KEY_LEN, "Remote Public Key (X||Y)");

//     psa_status_t status = dp_ble_ecdh(tmp_pub_key_buf, dhkey, sizeof(dhkey));

//     if (status != PSA_SUCCESS) {
//         err = -EIO;
//         LOG_ERR("Secure ECDH failed: %d", status);
//     } else {
//         LOG_HEXDUMP_INF(dhkey, TFN_ECDH_SHARED_KEY_LEN, "DH Key");
//     }

//     k_sched_lock();
//     if (dh_key_cb) {
//         bt_dh_key_cb_t cb = dh_key_cb;
//         dh_key_cb = NULL;
//         atomic_clear_bit(flags, PENDING_DHKEY);

//         if (err) {
//             cb(NULL);
//         } else {
//             // Convert DH key from big-endian to little-endian for Bluetooth stack
//             uint8_t dhkey_le[TFN_ECDH_SHARED_KEY_LEN];
//             sys_memcpy_swap(dhkey_le, dhkey, TFN_ECDH_SHARED_KEY_LEN);
//             cb(dhkey_le);
//         }
//     }
//     k_sched_unlock();
// }
//adding more than one private key


static void generate_dh_key(struct k_work *work)
  {
      int err = 0;
      uint8_t dhkey[TFN_ECDH_SHARED_KEY_LEN];
      uint8_t tmp_pub_key_buf[TFN_PUBKEY_EXPORT_LEN];

      // Validate private key ID
      if (current_private_key_id == 0) {
          LOG_ERR("No valid private key ID!");
          err = -EIO;
          goto exit;
      }

      tmp_pub_key_buf[0] = 0x04; // uncompressed
      memcpy(&tmp_pub_key_buf[1], dh_key_cb_remote_key, BT_PUB_KEY_LEN);

      LOG_INF("Using private key ID 0x%08x for ECDH", current_private_key_id);

      // Pass private key ID to ECDH service
      // Call secure partition to compute DH key

      psa_status_t status = dp_ble_ecdh(current_private_key_id,
                                        tmp_pub_key_buf,
                                        dhkey, sizeof(dhkey));

      if (status != PSA_SUCCESS) {
          err = -EIO;
          LOG_ERR("[ECC] Secure ECDH failed: %d", status);
      } else {
          // Extract DH Key ID from handle
          uint32_t dh_key_id;
          memcpy(&dh_key_id, dhkey, sizeof(uint32_t));
          LOG_INF("========================================");
          LOG_INF("[ECC] ✓ Received 32-byte handle from secure partition");
          LOG_INF("[ECC] First 4 bytes: %02x %02x %02x %02x",
                  dhkey[0], dhkey[1], dhkey[2], dhkey[3]);
          LOG_INF("[ECC] Extracted DH Key ID = %u (0x%08x)", dh_key_id, dh_key_id);
          LOG_INF("========================================");
      }

  exit:
      k_sched_lock();
      if (dh_key_cb) {
          bt_dh_key_cb_t cb = dh_key_cb;
          dh_key_cb = NULL;
          atomic_clear_bit(flags, PENDING_DHKEY);

          if (err) {
              cb(NULL);
          } else {
              // Extract and print DH Key ID before passing to SMP
              uint32_t dh_key_id_before_cb;
              memcpy(&dh_key_id_before_cb, dhkey, sizeof(uint32_t));
              LOG_INF("[ECC] Passing handle to SMP callback...");
              LOG_INF("[ECC] Handle first 4 bytes: %02x %02x %02x %02x",
                      dhkey[0], dhkey[1], dhkey[2], dhkey[3]);
              LOG_INF("[ECC] DH Key ID = %u (0x%08x)",
                      dh_key_id_before_cb, dh_key_id_before_cb);

              // Pass DH key handle directly to SMP (no swap)
              cb(dhkey);

              LOG_INF("[ECC] ✓ Handle passed to SMP");
          }

      }
      k_sched_unlock();
  }


//until here for adding more than one private keyy

int bt_pub_key_gen(struct bt_pub_key_cb *new_cb)
{
    LOG_INF("bt_pub_key_gen called");

    struct bt_pub_key_cb *cb;

    if (!new_cb) {
        return -EINVAL;
    }

    SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
        if (cb == new_cb) {
            LOG_WRN("Callback already registered");
            return -EALREADY;
        }
    }

    if (atomic_test_bit(flags, PENDING_DHKEY)) {
        LOG_WRN("Busy performing another ECDH operation");
        return -EBUSY;
    }

    sys_slist_prepend(&pub_key_cb_slist, &new_cb->node);

    if (atomic_test_and_set_bit(flags, PENDING_PUB_KEY)) {
        return 0;
    }

    atomic_clear_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);

    if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
        bt_long_wq_submit(&pub_key_work);
    } else {
        k_work_submit(&pub_key_work);
    }

    return 0;
}

void bt_pub_key_hci_disrupted(void)
{
    struct bt_pub_key_cb *cb;

    atomic_clear_bit(flags, PENDING_PUB_KEY);

    SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
        if (cb->func) {
            cb->func(NULL);
        }
    }

    sys_slist_init(&pub_key_cb_slist);
}

const uint8_t *bt_pub_key_get(void)
{
    if (atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
        LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "Secure Key (Big-Endian stored): ");
        LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "Secure Key (Little-Endian sent to BT): ");
        return pub_key;
    }

    if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
        LOG_INF("Using Debug Public Key");
        LOG_HEXDUMP_INF(debug_public_key, BT_PUB_KEY_LEN, "Debug Public Key: ");
        return debug_public_key;
    }

    return NULL;
}

int bt_dh_key_gen(const uint8_t remote_pk[BT_PUB_KEY_LEN], bt_dh_key_cb_t cb)
{
    if (dh_key_cb == cb) {
        return -EALREADY;
    }

    if (!atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
        return -EADDRNOTAVAIL;
    }

    if (dh_key_cb ||
        atomic_test_bit(flags, PENDING_PUB_KEY) ||
        atomic_test_and_set_bit(flags, PENDING_DHKEY)) {
        return -EBUSY;
    }

    dh_key_cb = cb;

    // Log the remote public key we received
    LOG_INF("=== REMOTE DEVICE PUBLIC KEY RECEIVED ===");
    LOG_HEXDUMP_INF(remote_pk, BT_PUB_KEY_LEN, "Remote Key (Little-Endian from BT)");

    // Convert remote public key from little-endian to big-endian
    sys_memcpy_swap(dh_key_cb_remote_key, remote_pk, BT_PUB_KEY_COORD_LEN);
    sys_memcpy_swap(&dh_key_cb_remote_key[BT_PUB_KEY_COORD_LEN],
            &remote_pk[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);

    LOG_HEXDUMP_INF(dh_key_cb_remote_key, BT_PUB_KEY_LEN, "Remote Key (Big-Endian for ECDH)");

    if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
        bt_long_wq_submit(&dh_key_work);
    } else {
        k_work_submit(&dh_key_work);
    }

    return 0;
}
