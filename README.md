# abysscrypt

`abysscrypt` is a multi-level dm-crypt encryption tool with a Qt-based GUI wizard. Create up to 108 levels of encryption on a single device or file container, each with its own cipher, key size, hash algorithm, and password/keyfile.

You don't need complex passwords for every level. Strategic placement of complex passwords at certain levels provides excellent security. The passwords are hashed by the chosen hashing algorithm at each level. Mix different ciphers and hash algorithms across levels to protect against algorithm-specific vulnerabilities. Each level multiplies the work required to break the encryption.

Sector offsets can be configured for hidden containers.

## Recent Changes

**PR #5 — Logic and security hardening (2026-02-15)**
- Refactored cipher discovery to robustly parse `/proc/crypto`, infer cipher/mode combinations, and cache results
- Hardened hash list: hardcoded known-good hashes for cryptsetup plain mode, excluding weak SHA1
- Generated scripts now use `set -uo pipefail` with explicit error checks (replaced fragile `set -e`)
- Root privilege checks and mount point validation in generated scripts
- Container file creation uses `/dev/urandom` instead of `/dev/zero` for plausible deniability
- Fixed offset handling in generated `cryptsetup` commands (offset appended as flag, not embedded in device path)
- Offset input in GUI now accepts 64-bit values (replaced 32-bit `QSpinBox` with validated `QLineEdit`)
- Removed dead code and unused imports

**PR #4 — XTS blocksize validation, hash discovery, modprobe guidance (2026-02-15)**
- XTS mode no longer offered for 64-bit block ciphers (blowfish, cast5, des) — XTS requires 128-bit blocks
- Hash types hardcoded (cryptsetup uses libgcrypt/openssl, not the kernel crypto API)
- Generated scripts use `${1:-}` to prevent unbound variable abort under `set -u`
- GUI intro page now shows `modprobe` commands for loading cipher kernel modules

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/abyss1.png" width=480>
<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/abyss2.png" width=480>
<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/abysslevels2.png" width=480>


## Features

- **Deep Encryption**: Create up to 108 nested encryption levels
- **Maximum Flexibility**: Customise cipher, key size, and hash algorithm for each level
- **Offset Support**: Hide encrypted data at custom sector offsets in the storage medium
- **Plain dm-crypt**: No headers, no metadata, fully transparent encryption (no LUKS)
- **Quantum Resistance**: Multi-level encryption provides enhanced security against future attacks
- **Container Support**: Works with both file containers and block devices
- **Script Generation**: Automatically generates mount/unmount bash scripts for review and execution

## Installation

Install dependencies (`cryptsetup`, `python3`, `PyQt5`):

Debian/Ubuntu/Mint: `sudo apt install cryptsetup python3 python3-pyqt5`

Fedora/RHEL/CentOS: `sudo dnf install cryptsetup python3 python3-qt5`

Arch Linux/Manjaro: `sudo pacman -S cryptsetup python python-pyqt5`

openSUSE: `sudo zypper install cryptsetup python3 python3-qt5`

## Loading Cipher Kernel Modules

The GUI discovers available ciphers by reading `/proc/crypto`. Many ciphers are provided as kernel modules that are **not loaded by default**. To make additional ciphers available in the GUI dropdown, load them first:

```bash
sudo modprobe twofish
sudo modprobe serpent
sudo modprobe camellia
sudo modprobe blowfish
sudo modprobe cast5
sudo modprobe cast6
sudo modprobe anubis
sudo modprobe xts
sudo modprobe cbc
```

> **Note:** `modprobe` requires root. However, the GUI itself does **not** require root — it only generates a bash script. You can run the GUI as a normal user, review the generated script to confirm it only makes `cryptsetup` calls, and then execute it as root.

##  Usage

```bash
git clone https://github.com/hairetikos/abysscrypt
cd abysscrypt
chmod +x abysscrypt
./abysscrypt
```

The GUI generates a mount and unmount script. To use them:

```bash
# Review the script first — confirm it only contains cryptsetup/mount calls
cat mount_script.sh

# Execute as root
sudo bash mount_script.sh /path/to/mountpoint
```

Root is required for `cryptsetup` when running the generated script.

In general, `[cipher]-xts-plain64` is a good choice for each level.

If you are unmounting and mounting the device manually, the `noatime` option avoids unnecessary filesystem write operations:

`sudo mount -o noatime [...]`

If you are creating an `ext4` filesystem manually on the final encrypted layer, consider these options:

```bash
mkfs.ext4 -O ^has_journal,^resize_inode -m 0 /dev/mapper/abysscrypt_N
```

This disables the journal (reduces write amplification inside encryption layers), disables online resizing (unneeded for a fixed-size encrypted volume), and sets reserved blocks to 0%.

> **Note on `metadata_csum`:** The default ext4 metadata checksum (`metadata_csum`) provides integrity verification for filesystem metadata. dm-crypt provides **confidentiality only**, not integrity checking. Keeping `metadata_csum` enabled is recommended unless you have a specific reason to disable it.

## Wiping / Randomising the Volume Before Use

Before creating your multi-level encrypted volume, the underlying storage should be filled with pseudorandom data. This prevents an adversary from distinguishing encrypted regions from unused space.

The fastest method is to set up a single-level plain dm-crypt, write zeroes through it (which emerge as ciphertext), then close it:

```bash
# 1. Open a throwaway plain dm-crypt layer
#    Use a disposable password — you will never need it again
sudo cryptsetup open /dev/sdX wipe_crypt --type plain --cipher aes-xts-plain64 --key-size 256 --hash sha256

# 2. Fill with zeroes (encrypted to pseudorandom on disk)
sudo dd if=/dev/zero of=/dev/mapper/wipe_crypt bs=1M status=progress

# 3. Close the throwaway layer
sudo cryptsetup close wipe_crypt
```

This is significantly faster than `dd if=/dev/urandom` because AES-NI hardware acceleration encrypts zeroes at near-disk-speed.

## Example of Hidden Crypts Using Offsets

The `--offset` flag in plain dm-crypt tells `cryptsetup` to begin the encrypted volume at a given sector number (each sector = 512 bytes). This allows hidden encrypted volumes to coexist on the same device.

### Understanding Offset Calculation

To place a hidden volume, you need to calculate a safe offset — a sector beyond which the outer filesystem will never write data. The formula:

```
offset_sectors = (bytes_used_by_outer_data + safety_margin) / 512
```

For example, if your outer filesystem uses ~2 MiB of data and you want a 1 MiB safety margin:

```
offset = (2 MiB + 1 MiB) / 512 = (3 × 1048576) / 512 = 6144 sectors
```

> **⚠ CRITICAL WARNING:** The outer filesystem and the hidden volume have **no awareness of each other**. Writing new data to the outer filesystem after creating the hidden volume may overwrite and **permanently destroy** the hidden volume's data. Always:
> 1. Place all desired files on the outer filesystem **first**
> 2. Unmount the outer filesystem
> 3. **Never mount the outer filesystem read-write again** after activating the hidden volume
> 4. If you must access the outer filesystem again, mount it **read-only** (`mount -o ro`)

### Step-by-Step Example

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/helloworld.png" width=480>

**1. Outer (decoy) volume at `/dev/vdb1`**

`exfat` is used for the unencrypted outer volume so it appears as a regular USB-accessible volume (readable by Windows, macOS, and Linux). Place your decoy files here, then unmount.

If using `ext4` for the outer volume instead, disable the journal and reserved space to prevent the filesystem from scattering data unpredictably across the device:

```bash
sudo mkfs.ext4 -O ^has_journal -m 0 /dev/sdX
```

Other filesystems such as `xfs`, `f2fs`, etc. may be used, but research their block allocation strategy first — some filesystems spread data across the entire device, which would overwrite hidden volumes regardless of offset.

> **Tip:** After placing decoy files, run `df` to check how many bytes are actually used. Calculate your offset from that value plus a generous safety margin.

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/hellounderworld.png" width=480>

**2. First hidden crypt — "underworld"**

A hidden encrypted volume inside the same partition, starting at an offset (e.g., 6144 sectors = 3 MiB from the start of the device). This volume uses its own filesystem (exfat in this example).

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/helloabyss.png" width=480>

**3. Second hidden crypt — "abyss"**

A further hidden crypt deeper into the volume, at an additional offset from the first hidden volume. This demonstrates nested hidden volumes at different offsets, each with their own multi-level encryption.

Multiple hidden volumes at different offsets can coexist, each with different encryption levels and configurations.

### Hidden Volume Size

The usable size of a hidden volume is:

```
hidden_size = total_device_size - (offset × 512)
```

If nesting multiple hidden volumes, each subsequent volume's offset must account for all preceding volumes. Plan your layout carefully — there is no undo.

## Description

`abysscrypt` provides a Qt-based wizard interface for creating nested dm-crypt volumes with multiple encryption levels. Each level can have completely different encryption settings, making it extremely difficult to break through all layers of security. The application generates ready-to-use shell scripts for mounting and unmounting your encrypted volumes.

**The generated script may be discarded after first use, but only if you are confident that you can recall the passphrase for each level, along with the cipher, key size, hash algorithm, and offset for every level.**

**This is not LUKS — there is NO metadata stored on the device. Either commit all parameters to memory, or keep the script in a secure location.**

## Plain dm-crypt vs LUKS

`abysscrypt` uses plain dm-crypt mode (not LUKS) for several important security advantages:

### How Plain dm-crypt Works

- **No Headers**: Plain dm-crypt stores no metadata or headers in the encrypted volume
- **Transparent Operation**: The encrypted data appears as random noise with no identifying signature
- **Parameter Requirements**: You must provide all parameters (cipher, key size, hash) at mount time
- **Silent Validation**: There is no built-in password check — a wrong password produces garbled data, not an error

### Advantages over LUKS

1. **Plausible Deniability**: No headers means there is no way to prove encryption exists on the device
2. **Resilience to Corruption**: If part of the data is corrupted, only that sector is affected (unlike LUKS where header corruption can make the entire volume inaccessible)
3. **Enhanced Privacy**: No signatures or markers that identify the data as encrypted
4. **Hidden Volumes**: Using offsets, encrypted volumes can be hidden within other data
5. **Algorithm Diversity**: Multiple encryption layers with different algorithms provide defence against future attacks that might break a single algorithm

### Offsets Explained

The offset feature specifies the starting sector for the encrypted volume on the storage medium. This enables:

- Hiding encrypted volumes beyond the region used by an outer filesystem
- Creating multiple independent encrypted volumes on a single device at different offsets
- Enhancing plausible deniability by placing encrypted data in regions that appear to be unused space

### Multi-Level Security Strategy

For optimal security:
- You don't need complex passwords for every level
- Strategic placement of complex passwords at certain levels provides excellent security
- Mix different ciphers across levels to protect against algorithm-specific vulnerabilities
- Each level multiplies the computational work required to break the encryption

### Known Issues

Some combinations of cipher, key size, and hash may not work when running the generated script. If `cryptsetup` rejects a combination, edit that level in the GUI and regenerate the script.

In general, `[cipher]-xts-plain64` is a reliable and well-tested choice.
