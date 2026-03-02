# plc-touch

Please Touch. Secure enclave based keys for ATProto PLC rotation keys.

> Named after the [Please Touch Museum](https://www.pleasetouchmuseum.org/)

A Rust TUI for managing AT Protocol (Bluesky) `did:plc` rotation keys with macOS Secure Enclave and Touch ID.

Take sovereign control of your DID PLC identity by generating hardware-backed P-256 keys and using them to directly sign and submit PLC operations — without needing your PDS to sign on your behalf.

## Features

- **Key Management** — Generate P-256 keys in the Secure Enclave (device-only, hardware-backed) or as software keys (synced via iCloud Keychain across Apple devices)
- **Touch ID Signing** — Every PLC operation signing triggers biometric authentication
- **DID Inspection** — View your DID document, rotation keys, verification methods, and services
- **PLC Operations** — Add/remove rotation keys, with diff preview before signing
- **Audit Log** — Browse the full PLC operation history for any DID
- **PDS Login** — Authenticate with your PDS for operations that require it (initial key addition via email token flow)
- **Test Posts** — Send posts to Bluesky from the TUI

## Screenshots

```
┌─plc-touch──did:plc:abc...xyz──🔑 mykey ● PDS─┐
│ 1 Keys  │ 2 Identity │ 3 Sign │ 4 Audit │ ...│
├───────────────────────────────────────────────┤
│ ┌ Secure Enclave Keys ───────────────────────┐│
│ │  ▸ mykey *                                 ││
│ │    did:key:zDnae...                        ││
│ │    iCloud Keychain (synced)  Touch ID      ││
│ └────────────────────────────────────────────┘│
│ q quit  ? help  1-6 tabs  n new  d del  s set │
└───────────────────────────────────────────────┘
```

## Requirements

- macOS 13+ (Ventura or later)
- Rust toolchain
- Apple Developer account (for Secure Enclave entitlements)
- Provisioning profile with `keychain-access-groups` entitlement

## Setup

1. **Clone and configure:**

```bash
git clone https://github.com/yourusername/plc-touch.git
cd plc-touch
cp .env.example .env
```

2. **Edit `.env`** with your Apple Developer signing details:

```
CODESIGN_IDENTITY="Apple Development: Your Name (XXXXXXXXXX)"
BUNDLE_ID="com.yourcompany.plc-touch"
TEAM_ID="XXXXXXXXXX"
```

3. **Create a provisioning profile** on [developer.apple.com](https://developer.apple.com):
   - Register your Mac's Provisioning UDID (find it in System Settings > General > About, or `system_profiler SPHardwareDataType | grep "Provisioning UDID"`)
   - Create a macOS App ID with your bundle ID
   - Create a macOS Development provisioning profile
   - Download and save as `embedded.provisionprofile` in the project root

4. **Build and sign:**

```bash
./build.sh
```

5. **Run:**

```bash
target/release/plc-touch.app/Contents/MacOS/plc-touch
```

## Usage

### Tabs

| Tab | Key | Description |
|-----|-----|-------------|
| Keys | `1` | Manage Secure Enclave / iCloud Keychain keys |
| Identity | `2` | Inspect DID document, rotation keys, verification methods |
| Sign | `3` | Review and sign staged PLC operations |
| Audit | `4` | Browse PLC operation audit log |
| Post | `5` | Send a test post to Bluesky |
| Login | `6` | Authenticate with your PDS |

### Key Bindings

**Global:**
- `1`-`6` — Switch tabs
- `?` — Help
- `q` — Quit

**Keys tab:**
- `n` — Generate new key (choose syncable or device-only)
- `d` — Delete selected key
- `s` — Set as active signing key
- `Enter` — Copy `did:key` to clipboard

**Identity tab:**
- `e` — Enter/change DID
- `r` — Refresh from PLC directory
- `a` — Add active key to rotation keys
- `x` — Remove selected rotation key
- `m` — Move rotation key (change priority)

**Sign tab:**
- `s` — Sign operation with Touch ID
- `j` — Toggle JSON view

**Audit tab:**
- `j`/`Enter` — Expand/collapse entry

### Key Types

When generating a key (`n`), you can toggle sync with `Tab`:

- **Syncable `[Y]`** — Software P-256 key stored in iCloud Keychain. Available on all your Apple devices. Touch ID enforced at app level before signing.
- **Device-only `[n]`** — Hardware-backed Secure Enclave key. Never leaves the chip. Touch ID enforced by hardware during signing. Only works on this device.

### Typical Flow

1. **Generate a key** — Tab 1, press `n`, enter a label, press `Enter`
2. **Set it active** — Press `s` on the key
3. **Log in to your PDS** — Tab 6, enter handle and app password
4. **Enter your DID** — Tab 2, press `e`, enter your `did:plc:...`
5. **Add key to rotation** — Tab 2, press `a` on your key
6. **Sign the operation** — Tab 3, press `s`, authenticate with Touch ID
7. **Submit** — Confirm submission to PLC directory

## Architecture

```
src/
├── main.rs          # Entry point, terminal setup/teardown
├── app.rs           # Application state, event loop, async task dispatch
├── enclave.rs       # Secure Enclave + iCloud Keychain key management
├── didkey.rs        # did:key encoding/decoding (P-256)
├── plc.rs           # PLC operations, DAG-CBOR serialization, CID computation
├── sign.rs          # DER→raw signature conversion, low-S normalization
├── directory.rs     # PLC directory HTTP client
├── atproto.rs       # AT Protocol XRPC client (session, posts)
├── event.rs         # Async message types
└── ui/
    ├── mod.rs       # Top-level layout, tab bar, modals
    ├── keys.rs      # Key list and management
    ├── identity.rs  # DID document display
    ├── operations.rs# Operation signing and diff view
    ├── audit.rs     # Audit log browser
    ├── login.rs     # PDS authentication
    ├── post.rs      # Post composer
    └── components.rs# Shared widgets
```

### Signing Flow

```
PLC Operation (JSON)
  → serialize_for_signing() (DAG-CBOR, canonical key ordering)
  → sign_operation()
    → SE key: SecKeyCreateSignature (hardware Touch ID)
    → Software key: LAContext biometric check → SecKeyCreateSignature
  → DER → raw r||s (64 bytes)
  → low-S normalization
  → base64url encode → sig field
  → compute CID → submit to plc.directory
```

## Development

```bash
# Run tests (no hardware required)
cargo test

# Build without signing (for development)
cargo build

# Build + codesign (required for Secure Enclave access)
./build.sh
```

## License

MIT
