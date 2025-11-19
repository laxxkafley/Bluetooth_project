# Key Flow Tracking: DH Key Handle, MacKey, and LTK

**Purpose**: Track exactly where each key/handle is created, passed, and used throughout the codebase.

---

## Table of Contents

1. [DH Key Handle Flow](#dh-key-handle-flow)
2. [MacKey Flow](#mackey-flow)
3. [LTK Flow](#ltk-flow)
4. [Summary Diagram](#summary-diagram)

---

## DH Key Handle Flow

### Step 1: DH Key Computed in Secure Partition

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_ecdh_service_ipc()`
**Lines**: 896-985

```c
// Line 970: Compute shared DH key using PSA Crypto
status = psa_raw_key_agreement(
    PSA_ALG_ECDH,
    sec_ble_keys[input.slot_index].key_id,  // Our private key
    remote_pub, 65,                          // Peer's public key
    sec_ble_keys[input.slot_index].dh_key, 32, &output_len  // ← DH key stored HERE
);

// Line 978: Mark DH key as valid
sec_ble_keys[input.slot_index].dh_key_valid = 1;
```

**What Happens**:
- DH key (32 bytes) is computed using our private key and peer's public key
- DH key is stored in `sec_ble_keys[0].dh_key[]` array
- DH key **NEVER leaves secure partition**

### Step 2: Return DH Key Handle (Not the Key Itself!)

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_ecdh_service_ipc()`
**Lines**: 981-984

```c
// Line 981-982: Pack slot_index as uint32_t in first 4 bytes
uint32_t slot_as_u32 = (uint32_t)input.slot_index;
memcpy(dh_key_handle, &slot_as_u32, sizeof(uint32_t));

// Line 984: Return 32-byte buffer (first 4 bytes = handle, rest = zeros)
psa_write(msg->handle, 0, dh_key_handle, 32);
```

**What Gets Returned**:
```
Bytes [0-3]:   0x00 0x00 0x00 0x00   ← slot_index = 0 (the HANDLE)
Bytes [4-31]:  0x00 ... 0x00         ← Padding (all zeros)
```

**Important**: We return the **slot index** (which slot the DH key is in), NOT the actual DH key!

### Step 3: Non-Secure Wrapper Receives Handle

**File**: `src/BLE_partition.c`
**Function**: `dp_ble_ecdh()`
**Lines**: 203-237

```c
// Line 224: Output buffer to receive "DH key" (actually the handle)
psa_outvec out_vec[] = {
    { .base = dhkey_out, .len = dhkey_size }  // dhkey_out is 32 bytes
};

// Line 233: Make PSA call - receives 32-byte handle buffer
status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, out_vec, 1);
```

**What `dhkey_out` Contains After Call**:
```
[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ..., 0x00]
  ^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^^
  slot_index = 0        padding (zeros)
```

### Step 4: ECC Layer Receives Handle

**File**: `subsys/bluetooth/host/ecc.c`
**Function**: `bt_dh_key_gen()`
**Lines**: ~300-350 (approximate - file was large)

```c
// After calling dp_ble_ecdh(), dhkey buffer contains the handle
status = dp_ble_ecdh(slot, remote_pk_raw, dhkey, 32);

// dhkey[0-3] contains slot_index
// dhkey[4-31] are zeros
```

### Step 5: Byte Swap (Important!)

**File**: `subsys/bluetooth/host/ecc.c`
**Lines**: After DH computation

```c
// The handle bytes get swapped (but since slot=0, it stays 0x00000000)
sys_memcpy_swap(dhkey_out, dhkey, 32);

// Before swap: 0x00 0x00 0x00 0x00 ...
// After swap:  0x00 0x00 0x00 0x00 ... (no change since all zeros for slot 0)
```

### Step 6: Handle Passed to SMP

**File**: `subsys/bluetooth/host/ecc.c`
**Function**: `bt_smp_dhkey_ready()`
**Line**: Calls callback with dhkey

```c
// Pass dhkey (containing handle) to SMP via callback
dh_cb(dhkey);  // dhkey contains the 32-byte handle buffer
```

### Step 7: SMP Stores Handle

**File**: `subsys/bluetooth/host/smp.c`
**Function**: `bt_smp_dhkey_ready()`
**Line**: ~3400 (approximate)

```c
// Store the "dhkey" (actually handle) in smp structure
memcpy(smp->dhkey, dhkey, 32);

// smp->dhkey[0-3] = slot_index (0x00000000)
// smp->dhkey[4-31] = zeros
```

### Step 8: Extract Handle for F5 Call

**File**: `subsys/bluetooth/host/smp.c`
**Function**: `compute_and_check_and_send_periph_dhcheck()`
**Lines**: 3475-3477

```c
// Line 3475-3477: Extract slot_index from first 4 bytes
uint32_t dh_handle_32bit;
memcpy(&dh_handle_32bit, smp->dhkey, sizeof(uint32_t));  // Read bytes [0-3]
uint8_t dh_handle = (uint8_t)dh_handle_32bit;            // dh_handle = 0

// Now we have: dh_handle = 0 (the slot index)
```

### Step 9: Pass Handle to F5

**File**: `subsys/bluetooth/host/smp.c`
**Function**: `compute_and_check_and_send_periph_dhcheck()`
**Lines**: 3485-3487

```c
// Line 3485: Pass dh_handle (slot index) to F5 service
psa_status_t status = dp_ble_f5(dh_handle, smp->rrnd, smp->prnd,
                                &smp->chan.chan.conn->le.init_addr,
                                &smp->chan.chan.conn->le.resp_addr);
```

### Step 10: F5 Uses Handle to Access Real DH Key

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_f5_service_ipc()`
**Lines**: 1125-1141

```c
// Line 1125: Use slot_index to access the REAL DH key in secure partition
status = psa_mac_compute(
    salt_key_id,
    PSA_ALG_CMAC,
    sec_ble_keys[input.slot_index].dh_key, 32,  // ← REAL DH key (32 bytes)
    t, 16, &output_len
);

// The real DH key is at: sec_ble_keys[0].dh_key[]
// We use input.slot_index (which is 0) to access it
```

**Summary of DH Key Handle Flow**:
```
┌─────────────────────────────────────────────────────────────┐
│ Secure Partition: ECDH Service                             │
│ Line 970: Compute DH key → sec_ble_keys[0].dh_key[]        │
│ Line 982: Pack slot_index (0) into 32-byte buffer          │
│ Line 984: Return handle buffer to non-secure               │
└─────────────────────────────────────────────────────────────┘
                           ↓ (32-byte handle)
┌─────────────────────────────────────────────────────────────┐
│ Non-Secure Wrapper: dp_ble_ecdh()                          │
│ Line 233: Receive 32-byte handle via psa_call()            │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ ECC Layer: bt_dh_key_gen()                                 │
│ Byte-swap handle (no effect for slot 0)                    │
│ Call callback with handle                                   │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ SMP Layer: bt_smp_dhkey_ready()                            │
│ ~Line 3400: Store handle in smp->dhkey[]                   │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ SMP Layer: compute_and_check_and_send_periph_dhcheck()     │
│ Line 3477: Extract slot_index from smp->dhkey[0-3]         │
│ Line 3485: Pass slot_index to F5                           │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Secure Partition: F5 Service                               │
│ Line 1125: Use slot_index to access REAL DH key            │
│ Access: sec_ble_keys[slot_index].dh_key[]                  │
└─────────────────────────────────────────────────────────────┘
```

---

## MacKey Flow

### Step 1: MacKey Derived in F5 Service

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_f5_service_ipc()`
**Lines**: 1177-1199

```c
// Line 1177-1184: Derive MacKey using AES-CMAC
status = psa_mac_compute(
    t_key_id,                              // T (from step 1)
    PSA_ALG_CMAC,
    m, sizeof(m),                          // Message with counter=0
    sec_ble_keys[input.slot_index].mackey, 16, &output_len  // ← MacKey stored HERE
);

// Line 1194-1199: Byte-swap MacKey (CRITICAL for compatibility)
for (int i = 0; i < 8; i++) {
    uint8_t temp = sec_ble_keys[input.slot_index].mackey[i];
    sec_ble_keys[input.slot_index].mackey[i] =
        sec_ble_keys[input.slot_index].mackey[15 - i];
    sec_ble_keys[input.slot_index].mackey[15 - i] = temp;
}
```

**Where MacKey Lives**:
- `sec_ble_keys[0].mackey[]` - 16 bytes in secure partition
- **NEVER returned to non-secure world**
- **NEVER leaves secure partition**

### Step 2: F5 Returns Nothing (Keys Stay Secure)

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_f5_service_ipc()`
**Line**: 1234

```c
// Line 1234: Return success, but NO output data
return PSA_SUCCESS;

// Note: MacKey and LTK stay in sec_ble_keys[0]
// Non-secure world gets NO keys, only status code
```

### Step 3: Non-Secure F5 Wrapper Returns Success

**File**: `src/BLE_partition.c`
**Function**: `dp_ble_f5()`
**Lines**: 270-281

```c
// Line 277: Call secure F5 - NO output vector!
status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, NULL, 0);
//                                                  ^^^^  ^
//                                                  no output

// Line 280: Return only status
return status;  // PSA_SUCCESS if keys derived successfully
```

**Important**: Non-secure code NEVER sees MacKey!

### Step 4: SMP Calls F5 (Gets Only Status)

**File**: `subsys/bluetooth/host/smp.c`
**Function**: `compute_and_check_and_send_periph_dhcheck()`
**Lines**: 3485-3491

```c
// Line 3485-3487: Call F5 service
psa_status_t status = dp_ble_f5(dh_handle, smp->rrnd, smp->prnd,
                                &smp->chan.chan.conn->le.init_addr,
                                &smp->chan.chan.conn->le.resp_addr);

// Line 3488-3491: Check status (no keys returned!)
if (status != PSA_SUCCESS) {
    LOG_ERR("[SMP-PERIPH] Secure F5 failed: %d", status);
    return BT_SMP_ERR_UNSPECIFIED;
}

// At this point: MacKey is in secure partition, smp.c doesn't have it!
```

### Step 5: F6 Uses MacKey from Secure Partition

**File**: `subsys/bluetooth/host/smp.c`
**Function**: `compute_and_check_and_send_periph_dhcheck()`
**Lines**: 3515-3522

```c
// Line 3516-3519: Call F6 - pass dh_handle (NOT MacKey!)
status = dp_ble_f6(dh_handle, smp->prnd, smp->rrnd, r, &smp->prsp[1],
                   &smp->chan.chan.conn->le.resp_addr,
                   &smp->chan.chan.conn->le.init_addr,
                   e);  // e = output check value

// F6 will use dh_handle to find MacKey in secure partition
```

### Step 6: F6 Service Accesses MacKey

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_f6_service_ipc()`
**Lines**: 1319-1334

```c
// Line 1319-1323: Byte-swap MacKey for use
uint8_t mackey_swapped[16];
for (int i = 0; i < 16; i++) {
    mackey_swapped[i] = sec_ble_keys[input.slot_index].mackey[15 - i];
}
//                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                    Accessing MacKey from secure storage!

// Line 1334: Import MacKey for CMAC
status = psa_import_key(&mackey_attr, mackey_swapped, 16, &mackey_id);

// Line 1340-1343: Use MacKey to compute check value
status = psa_mac_compute(mackey_id, PSA_ALG_CMAC,
                         m, sizeof(m),
                         check, 16, &output_len);
```

### Step 7: F6 Returns Only Check Value (Not MacKey!)

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_f6_service_ipc()`
**Lines**: 1368

```c
// Line 1368: Return ONLY the check value (16 bytes)
psa_write(msg->handle, 0, check, 16);

// MacKey stays in sec_ble_keys[0].mackey[]
// Non-secure gets only the RESULT of F6 computation
```

**Summary of MacKey Flow**:
```
┌─────────────────────────────────────────────────────────────┐
│ Secure Partition: F5 Service                               │
│ Line 1184: Derive MacKey → sec_ble_keys[0].mackey[]        │
│ Line 1199: Byte-swap MacKey                                │
│ Line 1234: Return PSA_SUCCESS (NO MacKey returned!)        │
│                                                             │
│ ✓ MacKey STAYS in secure partition                         │
└─────────────────────────────────────────────────────────────┘
                           ↓ (only status)
┌─────────────────────────────────────────────────────────────┐
│ Non-Secure: SMP Layer                                       │
│ Line 3485: Call F5, get PSA_SUCCESS                        │
│ Line 3516: Call F6 with dh_handle (not MacKey!)            │
│                                                             │
│ ✗ Non-secure NEVER sees MacKey                             │
└─────────────────────────────────────────────────────────────┘
                           ↓ (dh_handle)
┌─────────────────────────────────────────────────────────────┐
│ Secure Partition: F6 Service                               │
│ Line 1322: Access MacKey: sec_ble_keys[slot].mackey[]      │
│ Line 1334: Use MacKey for CMAC                             │
│ Line 1368: Return only check value (16 bytes)              │
│                                                             │
│ ✓ MacKey STAYS in secure partition                         │
└─────────────────────────────────────────────────────────────┘
                           ↓ (check value only)
┌─────────────────────────────────────────────────────────────┐
│ Non-Secure: SMP Layer                                       │
│ Line 3519: Receive check value in 'e'                      │
│ Line 3538: Send check to peer device                       │
│                                                             │
│ ✗ Non-secure NEVER sees MacKey                             │
└─────────────────────────────────────────────────────────────┘
```

**Key Point**: MacKey is the MOST PROTECTED key - it NEVER leaves secure partition!

---

## LTK Flow

### Step 1: LTK Derived in F5 Service

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_f5_service_ipc()`
**Lines**: 1204-1227

```c
// Line 1204: Change counter to 1 for LTK derivation
m[0] = 0x01;  // counter = 1 for LTK

// Line 1206-1211: Derive LTK using AES-CMAC
status = psa_mac_compute(
    t_key_id,                           // T (same as MacKey derivation)
    PSA_ALG_CMAC,
    m, sizeof(m),                       // Message with counter=1
    sec_ble_keys[input.slot_index].ltk, 16, &output_len  // ← LTK stored HERE
);

// Line 1220-1225: Byte-swap LTK (CRITICAL for compatibility)
for (int i = 0; i < 8; i++) {
    uint8_t temp = sec_ble_keys[input.slot_index].ltk[i];
    sec_ble_keys[input.slot_index].ltk[i] =
        sec_ble_keys[input.slot_index].ltk[15 - i];
    sec_ble_keys[input.slot_index].ltk[15 - i] = temp;
}

// Line 1229: Mark F5 as complete
sec_ble_keys[input.slot_index].f5_valid = 1;
```

**Where LTK Lives Initially**:
- `sec_ble_keys[0].ltk[]` - 16 bytes in secure partition
- Initially NOT returned (same as MacKey)

### Step 2: F5 Returns Success (LTK Stays in Secure Partition)

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_f5_service_ipc()`
**Line**: 1234

```c
// Line 1234: Return success, LTK NOT returned yet
return PSA_SUCCESS;

// LTK is in sec_ble_keys[0].ltk[] but not exposed yet
```

### Step 3: SMP Retrieves LTK After F5

**File**: `subsys/bluetooth/host/smp.c`
**Function**: `compute_and_check_and_send_periph_dhcheck()`
**Lines**: 3497-3507

```c
// Line 3497-3499: After F5 succeeds, retrieve LTK
LOG_INF("[SMP-PERIPH] Retrieving LTK from secure partition...");

status = dp_ble_get_ltk(dh_handle, smp->tk);
//                      ^^^^^^^^^  ^^^^^^^
//                      slot       output buffer

// Line 3501-3504: Check if retrieval succeeded
if (status != PSA_SUCCESS) {
    LOG_ERR("[SMP-PERIPH] Failed to retrieve LTK: %d", status);
    return BT_SMP_ERR_UNSPECIFIED;
}

// Now smp->tk contains the LTK (16 bytes)
```

**Important**: LTK is stored in `smp->tk` (confusing name - "tk" = "Temporary Key" but holds LTK in LE SC)

### Step 4: GET_LTK Wrapper Calls Service

**File**: `src/BLE_partition.c`
**Function**: `dp_ble_get_ltk()`
**Lines**: 342-370

```c
// Line 349: Prepare input (slot_index)
input.slot_index = dh_handle;  // slot_index = 0

// Line 352-357: Prepare input/output vectors
psa_invec in_vec[] = {
    { .base = &input, .len = sizeof(input) }
};
psa_outvec out_vec[] = {
    { .base = ltk_out, .len = 16 }  // 16-byte output buffer for LTK
};

// Line 366: Make PSA call to retrieve LTK
status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, out_vec, 1);
//                                                   ^^^^^^^^
//                                                   Output: LTK
```

### Step 5: GET_LTK Service Returns LTK

**File**: `dummy_partition/BLE_partition.c`
**Function**: `tfm_ble_get_ltk_service_ipc()`
**Lines**: 1327-1369

```c
// Line 1355-1358: Validate that F5 was called
if (!sec_ble_keys[input.slot_index].f5_valid) {
    printf("[SECURE] GET_LTK: ERROR - F5 not called yet\n");
    return PSA_ERROR_INVALID_ARGUMENT;
}

// Line 1363: Write LTK to non-secure world
psa_write(msg->handle, 0, sec_ble_keys[input.slot_index].ltk, 16);
//                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                        Return the ACTUAL LTK (16 bytes)

// Line 1365-1367: Log the security implications
printf("[SECURE] GET_LTK: ✓ LTK sent to non-secure world!\n");
printf("[SECURE] GET_LTK: Controller needs this for link encryption\n");
printf("[SECURE] GET_LTK: MacKey STILL SECURE (never returned)\n");
```

**Why LTK Must Be Returned**: BLE controller needs LTK to encrypt/decrypt link-layer packets

### Step 6: SMP Uses LTK

**File**: `subsys/bluetooth/host/smp.c`
**Lines**: After F6 succeeds (~3590+)

```c
// After pairing completes, smp->tk (containing LTK) is used by:
// 1. Link encryption
// 2. Stored in bond database
// 3. Used for reconnection

// The LTK is passed to controller for AES-CCM encryption
```

**Summary of LTK Flow**:
```
┌─────────────────────────────────────────────────────────────┐
│ Secure Partition: F5 Service                               │
│ Line 1211: Derive LTK → sec_ble_keys[0].ltk[]              │
│ Line 1225: Byte-swap LTK                                   │
│ Line 1234: Return PSA_SUCCESS (LTK NOT returned yet)       │
│                                                             │
│ ✓ LTK stored in secure partition                           │
└─────────────────────────────────────────────────────────────┘
                           ↓ (only status)
┌─────────────────────────────────────────────────────────────┐
│ Non-Secure: SMP Layer                                       │
│ Line 3485: Call F5, get PSA_SUCCESS                        │
│ Line 3499: Call dp_ble_get_ltk() to retrieve LTK           │
└─────────────────────────────────────────────────────────────┘
                           ↓ (dh_handle)
┌─────────────────────────────────────────────────────────────┐
│ Non-Secure Wrapper: dp_ble_get_ltk()                       │
│ Line 366: Make PSA call with output vector for LTK         │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ Secure Partition: GET_LTK Service                          │
│ Line 1363: Write LTK to output vector                      │
│ Line 1363: psa_write(..., sec_ble_keys[0].ltk, 16)         │
│                                                             │
│ ⚠ LTK IS RETURNED (necessary for controller)              │
│ ✓ MacKey STILL secure (not returned)                       │
└─────────────────────────────────────────────────────────────┘
                           ↓ (16-byte LTK)
┌─────────────────────────────────────────────────────────────┐
│ Non-Secure: SMP Layer                                       │
│ Line 3499: Receive LTK in smp->tk                          │
│ Later: Pass LTK to controller for encryption               │
│                                                             │
│ ✓ LTK exposed (necessary evil - controller limitation)     │
└─────────────────────────────────────────────────────────────┘
```

**Key Differences from MacKey**:
- MacKey: NEVER leaves secure partition
- LTK: Returned to non-secure world because controller needs it

---

## Summary Diagram

### Complete Key Flow from ECDH to Encryption

```
┌────────────────────────────────────────────────────────────────────────┐
│                    SECURE PARTITION (TrustZone)                       │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [1] ECDH Service (Line 970)                                          │
│      ├─ Input: Private key (PSA ID), Peer's public key               │
│      ├─ Compute: DH key = ECDH(private, peer_public)                 │
│      ├─ Store: sec_ble_keys[0].dh_key[] = DH key (32 bytes)          │
│      └─ Return: slot_index (0x00000000) ← HANDLE, NOT KEY!           │
│           │                                                            │
│           └──────────────────────────────┐                            │
│                                          ↓                             │
│  [2] F5 Service (Lines 1125, 1184, 1211)                              │
│      ├─ Input: slot_index (0), nonces, addresses                     │
│      ├─ Access: sec_ble_keys[0].dh_key[] ← REAL DH KEY              │
│      ├─ Derive: T = CMAC(salt, DH_key)                               │
│      ├─ Derive: MacKey = CMAC(T, msg_counter0)                       │
│      ├─ Store: sec_ble_keys[0].mackey[] = MacKey ← NEVER EXPOSED    │
│      ├─ Derive: LTK = CMAC(T, msg_counter1)                          │
│      ├─ Store: sec_ble_keys[0].ltk[] = LTK                           │
│      └─ Return: PSA_SUCCESS ← NO KEYS RETURNED!                      │
│           │                           │                                │
│           │ (MacKey stays)            │ (LTK retrievable)             │
│           ↓                           ↓                                │
│  [3] F6 Service (Line 1322)      [4] GET_LTK Service (Line 1363)     │
│      ├─ Input: slot_index            ├─ Input: slot_index            │
│      ├─ Access: sec_ble_keys[0]      ├─ Access: sec_ble_keys[0]     │
│      │         .mackey[]              │         .ltk[]                │
│      ├─ Compute: check =              └─ Return: LTK (16 bytes) ──┐  │
│      │   CMAC(MacKey, msg)                      ⚠ EXPOSED!        │  │
│      └─ Return: check (16 bytes)                                  │  │
│           ↓ (check only)                                          │  │
│           │                                                        │  │
└───────────┼────────────────────────────────────────────────────────┼──┘
            │                                                        │
            │                                                        │
┌───────────┼────────────────────────────────────────────────────────┼──┐
│           │              NON-SECURE WORLD                          │  │
├───────────┼────────────────────────────────────────────────────────┼──┤
│           ↓                                                        ↓  │
│  [5] SMP Layer (smp.c)                                                │
│      ├─ Line 3477: Extract slot_index from smp->dhkey[0-3]           │
│      ├─ Line 3485: Call F5(slot_index, ...) → PSA_SUCCESS            │
│      ├─ Line 3499: Call GET_LTK(slot_index) → Receive LTK            │
│      │             Store in smp->tk                                   │
│      ├─ Line 3516: Call F6(slot_index, ...) → Receive check 'e'      │
│      ├─ Line 3553: Call F6(slot_index, ...) → Receive check 're'     │
│      ├─ Line 3583: Verify: memcmp(smp->e, re, 16) == 0 ✓             │
│      └─ Line 3588: Send check 'e' to peer                            │
│           │                                                            │
│           ↓                                                            │
│  [6] Controller (Hardware)                                            │
│      └─ Uses: smp->tk (LTK) for AES-CCM link encryption              │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### Key Security Properties

| Key/Data | Where Stored | Exposed to Non-Secure? | Why? |
|----------|--------------|------------------------|------|
| **Private Key** | Secure: `sec_ble_keys[0].key_id` (PSA) | ❌ NO | Used only in secure ECDH |
| **DH Key** | Secure: `sec_ble_keys[0].dh_key[]` | ❌ NO | Used only in secure F5 |
| **DH Handle** | Both: smp->dhkey[0-3] = slot_index | ✅ YES | Just an index (0), not the key! |
| **MacKey** | Secure: `sec_ble_keys[0].mackey[]` | ❌ NEVER | Used only in secure F6 |
| **LTK** | Secure: `sec_ble_keys[0].ltk[]` | ⚠️ YES (via GET_LTK) | Controller needs it (hardware limitation) |
| **F6 Check** | Temporary: returned to SMP | ✅ YES | Just a MAC output, not sensitive |

### What Makes This Secure?

1. **Private Key**: Never leaves PSA key storage
2. **DH Key**: Computed in secure world, only handle (slot index) returned
3. **MacKey**: Most critical - derived and used ONLY in secure partition
4. **LTK**: Derived securely, exposed only when needed (controller requirement)

### Attack Scenarios

| Attack | Before (Non-Secure) | After (Secure) |
|--------|---------------------|----------------|
| **Memory dump** | Reveals all keys | Reveals only LTK and handles |
| **DH key theft** | Possible (in RAM) | Impossible (in secure partition) |
| **MacKey forgery** | Possible if MacKey stolen | Impossible (MacKey never exposed) |
| **DHKey check forgery** | Possible if MacKey stolen | Impossible (F6 in secure partition) |
| **LTK theft** | Possible | Still possible (necessary evil) |

---

## Quick Reference: Line Numbers

### DH Key Handle
- **Created**: `dummy_partition/BLE_partition.c:982` (pack slot_index)
- **Returned**: `dummy_partition/BLE_partition.c:984` (psa_write)
- **Received**: `src/BLE_partition.c:233` (psa_call output)
- **Stored**: `smp.c:~3400` (memcpy to smp->dhkey)
- **Extracted**: `smp.c:3475-3477` (read first 4 bytes)
- **Used**: `smp.c:3485` (pass to F5), `smp.c:3516` (pass to F6)

### MacKey
- **Derived**: `dummy_partition/BLE_partition.c:1184` (psa_mac_compute)
- **Swapped**: `dummy_partition/BLE_partition.c:1194-1199` (byte swap)
- **Stored**: `sec_ble_keys[0].mackey[]` (secure partition)
- **Used**: `dummy_partition/BLE_partition.c:1322` (access in F6)
- **NEVER returned to non-secure world!**

### LTK
- **Derived**: `dummy_partition/BLE_partition.c:1211` (psa_mac_compute)
- **Swapped**: `dummy_partition/BLE_partition.c:1220-1225` (byte swap)
- **Stored**: `sec_ble_keys[0].ltk[]` (secure partition)
- **Returned**: `dummy_partition/BLE_partition.c:1363` (psa_write in GET_LTK)
- **Received**: `smp.c:3499` (dp_ble_get_ltk call)
- **Stored**: `smp.c:3499` (smp->tk)
- **Used**: Later for controller encryption

---

**Document Version**: 1.0
**Last Updated**: 2025-11-03
**Related**: See IMPLEMENTATION_REPORT.md for full details
