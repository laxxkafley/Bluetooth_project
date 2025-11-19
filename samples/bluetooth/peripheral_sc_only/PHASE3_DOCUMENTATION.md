# Phase 3: Securing BLE Pairing with TrustZone-M

## Overview

Phase 3 implements **secure BLE pairing** using ARM TrustZone-M to protect cryptographic secrets during LE Secure Connections pairing.

**Goal**: Move all sensitive cryptographic operations (ECDH, F5, F6) from non-secure world to secure partition, ensuring private keys and derived secrets never leave the secure world.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│         NON-SECURE WORLD (Zephyr)               │
│                                                 │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐ │
│  │   SMP    │───▶│   ECC    │───▶│  main.c  │ │
│  └──────────┘    └──────────┘    └──────────┘ │
│       │               │                         │
│       │ PSA calls     │ PSA calls               │
│       ▼               ▼                         │
└─────────────────────────────────────────────────┘
                      │
        ══════════════╪══════════════
              TrustZone Boundary
        ══════════════╪══════════════
                      │
┌─────────────────────▼─────────────────────────┐
│      SECURE WORLD (TF-M Secure Partition)     │
│                                               │
│  ┌──────────────────────────────────────┐   │
│  │       BLE Secure Partition           │   │
│  │  (BLE_partition.c)                   │   │
│  │                                       │   │
│  │  Services:                            │   │
│  │  • KEYGEN  - Generate ECC keypair    │   │
│  │  • ECDH    - Compute DH key          │   │
│  │  • F5      - Derive MacKey & LTK     │   │
│  │  • F6      - Compute DHKey check     │   │
│  │  • GET_LTK - Retrieve LTK            │   │
│  │                                       │   │
│  │  Storage:                             │   │
│  │  • sec_ble_keys[] - Slot-based array │   │
│  │  • PSA Crypto - Key storage          │   │
│  └──────────────────────────────────────┘   │
└───────────────────────────────────────────────┘
```

---

## Key Design: PSA Key ID Flow

### Traditional Approach (Insecure)
```
ECC computes DH key → 32 raw bytes → Pass to SMP → Pass to F5
❌ Problem: Raw key bytes exposed in non-secure memory
```

### Our Approach (Secure)
```
1. Secure partition computes DH key → 32 raw bytes
2. Import to PSA → Get key ID (e.g., 0x40000003)
3. Pass key ID to non-secure world (only 4-byte handle)
4. When F5 needs the key → Export from PSA inside secure partition
5. Non-secure world never sees raw key bytes
✓ Only handles/IDs cross the security boundary
```

---

## Important Code Locations

### 1. Secure Partition Services
**File**: `dummy_partition/BLE_partition.c`

#### ECDH Service (Computes DH Key)
**Lines 1793-1870**

Key implementation:
```c
// Line 1822: Import DH key to PSA (PSA-only storage)
psa_key_attributes_t dh_attr = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_type(&dh_attr, PSA_KEY_TYPE_DERIVE);
psa_set_key_usage_flags(&dh_attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);

psa_key_id_t dh_key_id;
psa_import_key(&dh_attr, shared, sizeof(shared), &dh_key_id);

// Store only the key ID
sec_ble_keys[slot_index].dh_key_id = dh_key_id;

// Return handle (4-byte ID + 28 zeros padding)
uint8_t dh_key_handle[32];
memset(dh_key_handle, 0, 32);
memcpy(dh_key_handle, &dh_key_id, sizeof(uint32_t));
psa_write(msg->handle, 0, dh_key_handle, 32);
```

**Important**:
- DH key stored in PSA only (no raw bytes in memory)
- Export flag required for F5 to use it later
- Returns handle with ID, not actual key

---

#### F5 Service (Derives MacKey & LTK)
**Lines 1087-1267**

Key implementation:
```c
// Line 1117: Receive DH Key ID from non-secure world
uint32_t dh_key_id = input.dh_key_id;

// Line 1120: Find which slot owns this key ID
int slot_index = find_slot_by_dh_key_id(dh_key_id);

// Line 1129: Export DH key from PSA (inside secure world)
uint8_t dh_key[32];
psa_export_key(dh_key_id, dh_key, sizeof(dh_key), &output_len);

// Use dh_key for CMAC operations (BLE spec F5 algorithm)
// Step 1: T = CMAC(salt, dh_key)
// Step 2: MacKey = CMAC(T, ...)
// Step 3: LTK = CMAC(T, ...)

// Store in secure partition
sec_ble_keys[slot_index].mackey = ...;
sec_ble_keys[slot_index].ltk = ...;
```

**Important**:
- Export happens inside secure partition (non-secure cannot export)
- MacKey and LTK never leave secure partition
- Uses PSA-managed key via key ID

---

#### F6 Service (DHKey Check)
**Lines 1270-1335**

Key implementation:
```c
// Receive DH Key ID
int slot_index = find_slot_by_dh_key_id(input.dh_key_id);

// Use MacKey (stored in secure partition)
uint8_t *mackey = sec_ble_keys[slot_index].mackey;

// Compute check value using BLE spec F6 algorithm
psa_mac_compute(mackey_id, PSA_ALG_CMAC, m, sizeof(m), check_out, 16, ...);

// Return check value (public, sent over BLE)
psa_write(msg->handle, 0, check_out, 16);
```

**Important**:
- MacKey stays in secure partition
- Check value is public (sent over BLE for verification)

---

### 2. Non-Secure Code

#### ECC Layer
**File**: `subsys/bluetooth/host/ecc.c`
**Lines 1697-1747**

```c
// Line 1701: Call secure ECDH service
psa_status_t status = dp_ble_ecdh(current_slot_index,
                                   tmp_pub_key_buf,
                                   dhkey, sizeof(dhkey));

// Line 1709-1717: Receive handle from secure partition
uint32_t dh_key_id;
memcpy(&dh_key_id, dhkey, sizeof(uint32_t));
LOG_INF("[ECC] First 4 bytes: %02x %02x %02x %02x", ...);
LOG_INF("[ECC] Extracted DH Key ID = %u (0x%08x)", dh_key_id, dh_key_id);

// Line 1733: Pass handle to SMP (no byte swapping!)
cb(dhkey);
```

**Important**:
- No byte swapping on handle (it's an ID, not crypto material)
- Handle contains key ID + padding zeros

---

#### SMP Layer
**File**: `subsys/bluetooth/host/smp.c`
**Lines 3474-3565**

```c
// Line 3476: Extract DH Key ID from handle
uint32_t dh_key_id;
memcpy(&dh_key_id, smp->dhkey, sizeof(uint32_t));

// Line 3488: Call secure F5 service with key ID
psa_status_t status = dp_ble_f5(dh_key_id, smp->rrnd, smp->prnd, ...);

// Line 3499: Retrieve LTK from secure partition
status = dp_ble_get_ltk(dh_key_id, smp->tk);

// Line 3519: Call secure F6 service
status = dp_ble_f6(dh_key_id, ..., e);
```

**Important**:
- SMP only has key ID, never raw key bytes
- All crypto operations delegated to secure partition

---

### 3. Wrapper Functions (Non-Secure → Secure Bridge)

**File**: `src/BLE_partition.c`

These wrappers package data and call secure services via PSA IPC:

```c
// Line 248: F5 wrapper
psa_status_t dp_ble_f5(uint32_t dh_key_id, ...)
{
    struct f5_input_ns input;
    input.dh_key_id = dh_key_id;  // Pass key ID, not key bytes

    psa_handle_t handle = psa_connect(TFM_BLE_F5_SERVICE_SID, ...);
    status = psa_call(handle, PSA_IPC_CALL, in_vec, 1, NULL, 0);
}
```

---

## Security Verification

### Test Results

We tested attempting to access secrets from non-secure world:

```
==========================================================
              SECURITY TEST SUMMARY
==========================================================
  Private Key:  Protected in secure PSA                ✓
  DH Key:       Protected in secure PSA                ✓
  MacKey:       Protected in secure partition memory   ✓
  Only exposed: Key IDs (handles) and public outputs   ✓
==========================================================
```

### What's Protected

| Secret | Storage Location | Accessible from Non-Secure? |
|--------|------------------|------------------------------|
| **Private Key** | Secure PSA only | ❌ NO (export fails) |
| **DH Key** | Secure PSA only | ❌ NO (export fails with error -135) |
| **MacKey** | sec_ble_keys[] in secure partition | ❌ NO (no API exists) |
| **LTK** | sec_ble_keys[] in secure partition | ⚠️ YES (intentional - needed by controller) |

### What's Exposed

| Data | Size | Security Impact |
|------|------|-----------------|
| **Key IDs** | 4 bytes | ✓ Safe - Just handles, useless without secure partition |
| **Public Keys** | 65 bytes | ✓ Safe - Meant to be public |
| **F6 Check Values** | 16 bytes | ✓ Safe - Sent over BLE anyway |
| **LTK** | 16 bytes | ⚠️ Necessary - Controller needs it for encryption |

---

## Pairing Verification

### Test Output

```
[ECC] DH Key ID = 1073741827 (0x40000003)
[SMP] Extracted DH Key ID = 1073741827 (0x40000003)
[SMP] F5 success - MacKey and LTK stored in secure partition
[SMP] ✓ LTK retrieved from secure partition

[SMP] Expected Remote DHKey Check (Eb):
ec 47 3c 79 40 a0 22 2f  c6 71 69 cc f4 ff e2 dc

[SMP] Received Remote DHKey Check:
ec 47 3c 79 40 a0 22 2f  c6 71 69 cc f4 ff e2 dc

[SMP] ✓ DHKey Check MATCHED! Crypto is correct!

Security changed: level 4
Pairing Complete
```

### Proof of Correctness

1. **Key ID Flow**: Same ID (0x40000003) from secure partition → ECC → SMP ✓
2. **F5 Success**: LTK derived and retrieved ✓
3. **F6 Verification**: DHKey check values match perfectly ✓
4. **Security Level 4**: LE Secure Connections authenticated pairing ✓

The DHKey check matching proves:
- Both devices computed the same ECDH shared secret
- All cryptographic operations are correct
- PSA key export and usage works properly

---

## Key Data Structures

### Secure Partition Key Storage
**File**: `dummy_partition/BLE_partition.c` (Lines 21-32)

```c
struct ble_key_slot {
    psa_key_id_t key_id;        // Private key ID (never exported)
    uint8_t in_use;             // Slot occupied flag
    uint8_t conn_index;         // Connection identifier
    psa_key_id_t dh_key_id;     // DH key ID (for F5/F6 lookup)
    uint8_t mackey[16];         // MacKey (stays in secure world)
    uint8_t ltk[16];            // LTK (retrievable for controller)
    uint8_t f5_valid;           // F5 derivation completed flag
};

static struct ble_key_slot sec_ble_keys[MAX_BLE_CONNECTIONS];
```

**Important**: All sensitive data stored in secure partition memory only.

---

## Configuration

### Project Configuration
**File**: `prj.conf`

```conf
CONFIG_BUILD_WITH_TFM=y                        # Enable TrustZone-M
CONFIG_TFM_PROFILE_TYPE_NOT_SET=y              # Custom TF-M profile
CONFIG_TFM_CONNECTION_BASED_SERVICE_API=y      # Enable PSA IPC
```

### Partition Manifest
**File**: `dummy_partition/tfm_dummy_partition.yaml`

Defines secure services with unique SIDs (Service IDs):
- `TFM_BLE_KEYGEN_SERVICE_SID`: 0x00000090
- `TFM_BLE_ECDH_SERVICE_SID`: 0x00000091
- `TFM_BLE_F5_SERVICE_SID`: 0x00000092
- `TFM_BLE_F6_SERVICE_SID`: 0x00000093
- `TFM_BLE_GET_LTK_SERVICE_SID`: 0x00000094

---

## Build Instructions

```bash
cd /home/jasmine/zephyrproject/zephyr/samples/bluetooth/peripheral_sc_only
west build -b nrf5340dk/nrf5340/cpuapp/ns --pristine
west flash
```

---

## Summary

Phase 3 successfully implements secure BLE pairing with:

✅ **Private keys** protected in secure PSA
✅ **DH keys** protected in secure PSA
✅ **MacKey** protected in secure partition memory
✅ **Handle-based architecture** - only IDs cross security boundary
✅ **PSA Crypto** properly used for key management
✅ **Level 4 security** achieved (highest BLE security)
✅ **Security verified** - non-secure world cannot access secrets

All cryptographic secrets remain in the secure world, while non-secure world only handles key IDs and public outputs.
