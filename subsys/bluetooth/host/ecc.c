

 #include <stdint.h>

 #include <zephyr/sys/byteorder.h>
 #include <zephyr/sys/check.h>
 #include <zephyr/bluetooth/hci.h>
 
 #include <psa/crypto.h>
 
 #include "long_wq.h"
 #include "ecc.h"
 #include "hci_core.h"
 
 #define LOG_LEVEL CONFIG_BT_HCI_CORE_LOG_LEVEL
 #include <zephyr/logging/log.h>
 LOG_MODULE_REGISTER(bt_ecc);

 //#define CONFIG_JASMIN_CHANGE
 
 static uint8_t pub_key[BT_PUB_KEY_LEN];
 // pub_key: Stores the ECC public key.
 // pub_key_cb_slist: A linked list to hold callback functions for handling public key operations.
 // dh_key_cb: A callback function for handling Diffie-Hellman (DH) key exchange.
 static sys_slist_t pub_key_cb_slist;
 static bt_dh_key_cb_t dh_key_cb;
 
 static void generate_pub_key(struct k_work *work);
 static void generate_dh_key(struct k_work *work);
 K_WORK_DEFINE(pub_key_work, generate_pub_key);
 K_WORK_DEFINE(dh_key_work, generate_dh_key);
 
 enum {
	 PENDING_PUB_KEY,
	 PENDING_DHKEY,
 
	 /* Total number of flags - must be at the end of the enum */
	 NUM_FLAGS,
 };
 
 static ATOMIC_DEFINE(flags, NUM_FLAGS);
 //Soring public and private key
 static struct {
	 uint8_t private_key_be[BT_PRIV_KEY_LEN];
 
	 union {
		 uint8_t public_key_be[BT_PUB_KEY_LEN];
		 uint8_t dhkey_be[BT_DH_KEY_LEN];
	 };
 } ecc;
 static psa_key_id_t global_key_id; // lalalalalalalalallala


 psa_key_id_t my_key_id;
 
 // Predefined debug keys for testing ECC operations.
 /* based on Core Specification 4.2 Vol 3. Part H 2.3.5.6.1 */
 static const uint8_t debug_private_key_be[BT_PRIV_KEY_LEN] = {
	 0x3f, 0x49, 0xf6, 0xd4, 0xa3, 0xc5, 0x5f, 0x38,
	 0x74, 0xc9, 0xb3, 0xe3, 0xd2, 0x10, 0x3f, 0x50,
	 0x4a, 0xff, 0x60, 0x7b, 0xeb, 0x40, 0xb7, 0x99,
	 0x58, 0x99, 0xb8, 0xa6, 0xcd, 0x3c, 0x1a, 0xbd,
 };
 
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
 
 // Compares a given public key with the predefined debug public key.
 // Returns true if they match.
 bool bt_pub_key_is_debug(uint8_t *cmp_pub_key)
 {
	 return memcmp(cmp_pub_key, debug_public_key, BT_PUB_KEY_LEN) == 0;
 }
 
 // public key validation
 
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
 
	 /* PSA expects secp256r1 public key to start with a predefined 0x04 byte */
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
 
	//  LOG_ERR("psa_import_key() returned status %d", ret);
	 return false;
 }
 
 // Configures ECC key attributes for key pair generation.
 // The key:
 
 //     Can be exported.
 //     Can be used for key derivation (ECDH).
 
 static void set_key_attributes(psa_key_attributes_t *attr)
 {
	 psa_set_key_type(attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	 psa_set_key_bits(attr, 256);
	 #ifdef CONFIG_JASMIN_CHANGE
	 psa_set_key_usage_flags(attr, PSA_KEY_USAGE_DERIVE);
	 #else
	 psa_set_key_usage_flags(attr, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_DERIVE);
	 #endif
	 psa_set_key_algorithm(attr, PSA_ALG_ECDH);
 }
 
 // Generating an ECC Public KeyCalls psa_generate_key() to create an ECC key pair.
 // If the operation fails, logs an error and exits.
//  LOG_INF("Calling generate_pub_key()...");



 
 static void generate_pub_key(struct k_work *work)
 {
	 LOG_INF("generate_pub_key() was triggered");
	

	 psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	 struct bt_pub_key_cb *cb;
	 psa_key_id_t key_id;
	 uint8_t tmp_pub_key_buf[BT_PUB_KEY_LEN + 1];
	 size_t tmp_len;
	 int err;
	 psa_status_t ret;
 
	 set_key_attributes(&attr);
	 
	 
	 ret = psa_generate_key(&attr, &global_key_id); 

	 LOG_INF("psa_generate_key() returned: %d", ret);  // Add this line //jasmine
	
	 if (ret != PSA_SUCCESS) {
		 LOG_ERR("Failed to generate ECC key %d", ret);
		 err = BT_HCI_ERR_UNSPECIFIED;
		 goto done;
	 } 
 
	 ret = psa_export_public_key(global_key_id, tmp_pub_key_buf, sizeof(tmp_pub_key_buf), &tmp_len); //lalalalalalallala replace key_id
	 LOG_INF("psa_export_public_key() returned: %d", ret);  // Add this line //jasmine
	 if (ret != PSA_SUCCESS) {
		 LOG_ERR("Failed to export ECC public key %d", ret);
		 err = BT_HCI_ERR_UNSPECIFIED;
		 goto done;
	 }else {
		// Success - do something after successful key export
		// LOG_INF("EXPORTED ECC PUBLIC KEY");
		// LOG_HEXDUMP_INF(tmp_pub_key_buf, tmp_len, "Public Key Data");
	 }
	 /* secp256r1 PSA exported public key has an extra 0x04 predefined byte at
	  * the beginning of the buffer which is not part of the coordinate so
	  * we remove that.
	  */
	 
	  memcpy(ecc.public_key_be, &tmp_pub_key_buf[1], BT_PUB_KEY_LEN);// After copying the public key into ecc.public_key_be
	  LOG_INF("LOCAL PUBLLIC KEY after copying from buffer: ");
	   LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "local Public Key");//jasmine
	
	 
	 
	 
//  // Exports the private key and stores it.
// 	 ret = psa_export_key(key_id, ecc.private_key_be, BT_PRIV_KEY_LEN, &tmp_len);
// 	 if (ret != PSA_SUCCESS) {
// 		 LOG_ERR("Failed to export ECC private key %d", ret);
// 		 err = BT_HCI_ERR_UNSPECIFIED;
// 		 goto done;
// 	 }


	//  // Destroys the generated key to ensure security.
	//  ret = psa_destroy_key(key_id);
	//  if (ret != PSA_SUCCESS) {
	// 	 LOG_ERR("Failed to destroy ECC key ID %d", ret);
	// 	 err = BT_HCI_ERR_UNSPECIFIED;
	// 	 goto done;
	//  }
 
	 // sys_memcpy_swap() is likely a helper function that copies and swaps the byte order from big-endian to little-endian.
 
	 sys_memcpy_swap(pub_key, ecc.public_key_be, BT_PUB_KEY_COORD_LEN);
	 sys_memcpy_swap(&pub_key[BT_PUB_KEY_COORD_LEN],
			 &ecc.public_key_be[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);
 
	 atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);
	 err = 0;
	 // atomic_set_bit() sets a specific bit in bt_dev.flags, marking that the public key is now available.
	 // Cleanup and Callback Execution
 done:
	 atomic_clear_bit(flags, PENDING_PUB_KEY);

	 LOG_INF("Before generate_dh_key, see local PUBLIC KEY:");
	 LOG_HEXDUMP_INF(ecc.public_key_be, BT_PUB_KEY_LEN, "Public Key Data Before generate_dh_key");
 
	 /* Change to cooperative priority while we do the callbacks */
	 k_sched_lock();

	
 
	 SYS_SLIST_FOR_EACH_CONTAINER(&pub_key_cb_slist, cb, node) {
		 if (cb->func) {
			 cb->func(err ? NULL : pub_key);
		 }
	 }
 
	 sys_slist_init(&pub_key_cb_slist);
 
	 k_sched_unlock();
	 
 }
 

 // This function performs ECDH key agreement to derive a shared secret key.
 static void generate_dh_key(struct k_work *work)
 {
	// LOG_INF("YOOOOOOOOOOOOOOOOOOOOOOO i m hngry");
	 int err;
 
	 psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	//  psa_key_id_t key_id;
	 psa_status_t ret;
	 
	 /* PSA expects secp256r1 public key to start with a predefined 0x04 byte
	  * at the beginning the buffer.
	  */
	 uint8_t tmp_pub_key_buf[BT_PUB_KEY_LEN + 1] = { 0x04 };
	 size_t tmp_len;
 
	 set_key_attributes(&attr);
	=
	 
	 if(IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
		LOG_INF("Debug key is used.... We shouldnt use it....");
		LOG_INF("Debug Private Key: %s", debug_private_key_be);
	 } else {
		LOG_INF("Fresh ecc key was generated. and being used for dhkey...");
		LOG_INF("Generated Private Key: %s", ecc.private_key_be);
	 }
 
	 const uint8_t *priv_key = (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS) ?
					debug_private_key_be :
					ecc.private_key_be);


					//lalalal i commented import

			
					
	//  ret = psa_import_key(&attr, priv_key, BT_PRIV_KEY_LEN, &global_key_id); //lalalalalalalalla cahnge from&key_id
	//  if (ret != PSA_SUCCESS) {
	// 	 err = -EIO;
	// 	 LOG_ERR("Failed to import the private key for key agreement %d", ret);
	// 	 goto exit;
	//  }
	 // Performing Key Agreement (ECDH)
 
	 
	 // What Happens Here?
 
	 // Your device and another device exchange public keys.
	 // Using your private key and the other party's public key, you compute the shared secret (DH Key).
 
 
	 memcpy(&tmp_pub_key_buf[1], ecc.public_key_be, BT_PUB_KEY_LEN);
 
 
	 // psa_raw_key_agreement: This function performs the ECDH key agreement. It uses the private key (key_id) and the other party's public key (tmp_pub_key_buf) to derive the shared secret key, which is then stored in ecc.dhkey_be.
	 
	 ret = psa_raw_key_agreement(PSA_ALG_ECDH, global_key_id, tmp_pub_key_buf, sizeof(tmp_pub_key_buf), //lalalalalla replace key-id
					 ecc.dhkey_be, BT_DH_KEY_LEN, &tmp_len);
	 if (ret != PSA_SUCCESS) {
		 err = -EIO;
		 LOG_ERR("Raw key agreement failed %d", ret);
		 goto exit;
	 }
	
 
 
	//  ret = psa_destroy_key(key_id);
	//  if (ret != PSA_SUCCESS) {
	// 	 LOG_ERR("Failed to destroy the key %d", ret);
	// 	 err = -EIO;
	// 	 goto exit;
	//  }
	
	//uncomment this

	//  LOG_INF("ECC Private Key for nrf5340 (debugging only): ");
	//  LOG_HEXDUMP_INF(ecc.private_key_be, BT_PRIV_KEY_LEN, "Private Key");
	 
	 
	//  LOG_HEXDUMP_INF(tmp_pub_key_buf, BT_PUB_KEY_LEN, "REMOTEE Public Key from key arrangement step");//jasmine
	//uncomment this
	 err = 0;
 
 exit:
	 /* Change to cooperative priority while we do the callback */
	 k_sched_lock();
 
	 if (dh_key_cb) {
		 bt_dh_key_cb_t cb = dh_key_cb;
 
		 dh_key_cb = NULL;
		 atomic_clear_bit(flags, PENDING_DHKEY);
 
		 if (err) {
			 cb(NULL);
		 } else {
			 uint8_t dhkey[BT_DH_KEY_LEN];
 
			 sys_memcpy_swap(dhkey, ecc.dhkey_be, sizeof(ecc.dhkey_be));
			 LOG_INF("DERIVED DH KEY");
			 LOG_HEXDUMP_INF(dhkey, BT_DH_KEY_LEN, "DH Key");
			 cb(dhkey);
 
		 }
	 }
 
	 k_sched_unlock();
 }
 
 int bt_pub_key_gen(struct bt_pub_key_cb *new_cb){
	LOG_INF("JASMIN: bt_pub_key_gen called");
	 struct bt_pub_key_cb *cb;
 
	 if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
		LOG_INF("Using debug keys - skipping regular key generation");
		 atomic_set_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY);
		 __ASSERT_NO_MSG(new_cb->func != NULL);

		 
		 new_cb->func(debug_public_key);
		 return 0;
	 }
 
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
	 
 
	 LOG_INF("JASMIN: putting pub_key worker in the queue");
	
	 if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
		 bt_long_wq_submit(&pub_key_work);
		 LOG_INF("Submitting to long WQ: %d", IS_ENABLED(CONFIG_BT_LONG_WQ));

	 } else {
		 k_work_submit(&pub_key_work);
	 
	}
	LOG_INF("After submit to WQ");

	 
 
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
	 if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
		LOG_INF("Using Debug Public Key"); //jasmine-mobile-debug
		LOG_HEXDUMP_INF(debug_public_key, BT_PUB_KEY_LEN, "Debug Public Key: ");
		 return debug_public_key;
	 }
 
	 if (atomic_test_bit(bt_dev.flags, BT_DEV_HAS_PUB_KEY)) {
		LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "NRFFFFFFFFFFFFF Public Key: ");

		
		 return pub_key;
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



///////////////////////////////////////////////
	//   Log whether the device is using debug keys or the generated public key
	//   if (IS_ENABLED(CONFIG_BT_USE_DEBUG_KEYS)) {
    //     LOG_INF("Using Debug Keys for DH Key Generation");
    //     LOG_HEXDUMP_INF(debug_public_key, BT_PUB_KEY_LEN, "Debug Public Key: ");
    // } else {
    //     LOG_INF("Using Generated Mobile Device Public Key for DH Key Generation");
    //     LOG_HEXDUMP_INF(pub_key, BT_PUB_KEY_LEN, "Mobile Public Key: ");
	// 	//////////////////////////////////////////////////////////
    // }

 
	 /* Convert X and Y coordinates from little-endian to
	  * big-endian (expected by the crypto API).
	  */
	 sys_memcpy_swap(ecc.public_key_be, remote_pk, BT_PUB_KEY_COORD_LEN);
	 sys_memcpy_swap(&ecc.public_key_be[BT_PUB_KEY_COORD_LEN],
			 &remote_pk[BT_PUB_KEY_COORD_LEN], BT_PUB_KEY_COORD_LEN);
 
	 if (IS_ENABLED(CONFIG_BT_LONG_WQ)) {
		 bt_long_wq_submit(&dh_key_work);
	 } else {
		 k_work_submit(&dh_key_work);
	 }
 
	 return 0;
 }
 
 #ifdef ZTEST_UNITTEST
 uint8_t const *bt_ecc_get_public_key(void)
 {
	 return pub_key;
 }
 
 uint8_t const *bt_ecc_get_internal_debug_public_key(void)
 {
	 return debug_public_key;
 }
 
 sys_slist_t *bt_ecc_get_pub_key_cb_slist(void)
 {
	 return &pub_key_cb_slist;
 }
 
 bt_dh_key_cb_t *bt_ecc_get_dh_key_cb(void)
 {
	 return &dh_key_cb;
 }
 #endif /* ZTEST_UNITTEST */
 
 
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