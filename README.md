# abysscrypt

`abysscrypt` is a powerful multi-level dm-crypt encryption solution with a user-friendly GUI wizard.  Create up to 108 levels of encryption on a single device or file container each with their own cipher, keysize, hash algorithm, and password/keyfile.

You don't need complex passwords for every level.  Strategic placement of complex passwords at certain levels provides excellent security.  The passwords are hashed by the chosen hashing algorithm at each level.  Mix different ciphers and hash algorithms across levels to protect against algorithm-specific vulnerabilities.  Each level multiplies the work required to break the encryption.

Sector offsets can be configured for hidden containers.

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/abyss1.png" width=480>
<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/abyss2.png" width=480>
<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/abysslevels2.png" width=480>


## Features

- **Deep Encryption**: Create up to 108 nested encryption levels
- **Maximum Flexibility**: Customize cipher, key size, and hash algorithm for each level
- **Offset Support**: Hide encrypted data at custom offsets in the storage medium
- **Plain dm-crypt**: No headers, fully transparent encryption (no LUKS)
- **Quantum Resistance**: Multi-level encryption provides enhanced security against future attacks
- **Container Support**: Works with both file containers and block devices
- **Script Generation**: Automatically generates mount/unmount scripts

## Installation

install dependencies (`cryptsetup`, `python3`, `qt5`)

Debian/Ubuntu/Mint  `sudo apt install cryptsetup python3 python3-qtpy-pyqt5 `

Fedora/RHEL/CentOS  `sudo dnf install cryptsetup python3 python3-qt5`

Arch Linux/Manjaro  `sudo pacman -S cryptsetup python python-pyqt5`

openSUSE  `sudo zypper install cryptsetup python3 python3-qt5`

##  Usage

```bash
git clone https://github.com/hairetikos/abysscrypt
cd abysscrypt
chmod +x abysscrypt
./abysscrypt
```
to use the generated mount script:

`sudo bash mount_script.sh /path/to/mountpoint`

root is required for dm-crypt/cryptsetup when running the script

`abysscrypt` GUI can be ran in non-root mode to generate the script, but it may not enumerate *all* available hashing algorithms.

in general `[cipher]-xts-plain64` is a good option for each level.

## to make the data appear random/wipe the volume before usage:

make a simple 1 or 2 level plain dm-crypt on the target first (do not use LUKS), choose aes-xts-plain64 for good speed and security, choose a strong hashing algorithm such as sha512, spam your keyboard when providing the password, do not mount it (or, unmount it first), then invoke:

`sudo dd if=/dev/zero of=/dev/mapper/crypt`

the zeroes we be garbled via encryption and fill the device like random data. this is much faster than using `/dev/urandom` to fill it with random data.

## Example of Hidden Crypts using Offsets

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/helloworld.png" width=480>

here is the base partition, without encryption at /dev/vdb1

exfat filesystem is used because of less metadata that may be corrupted by the hidden crypt container (fat32 can also be used).  Other filesystems may be used, but if they have more metadata and journaling, then more careful meticulous planning of the offset needs to be done, and corruption is more likely.  exfat is also already common for USB sticks...

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/hellounderworld.png" width=480>

we then have a hidden crypt "underworld" inside this volume at an offset of 6018 sectors, again using exfat.

<img src="https://github.com/hairetikos/abysscrypt/blob/main/ss/helloabyss.png" width=480>

then, even further down, at the 5th level, we have ANOTHER hidden crypt "abyss" within the volume at a further of 6018 sectors from the first hidden volume, again using exfat

we can have many levels and configurations!

## Description

`abysscrypt` provides a Qt-based wizard interface for creating nested dm-crypt volumes with multiple encryption levels. Each level can have completely different encryption settings, making it extremely difficult to break through all layers of security. The application generates ready-to-use shell scripts for mounting and unmounting your encrypted volumes.

**The script may be discarded after first use, but only if you are confident that you can remember passphrases for each level, along with their ciphers, key sizes, and hashes!**

**this is not LUKS, there is NO metadata... either remember everything with mnemonic techniques, or keep the script safe.**

## Plain dm-crypt vs LUKS

`abysscrypt` uses plain dm-crypt mode (not LUKS) for several important security advantages:

### How Plain dm-crypt Works

- **No Headers**: Plain dm-crypt doesn't store any metadata or headers in the encrypted volume
- **Transparent Operation**: The encrypted data appears as random noise without any signature
- **Parameter Requirements**: You must provide all parameters (cipher, key size, hash) at mount time
- **Silent Validation**: There's no built-in password check - wrong passwords produce garbled data rather than errors

### Advantages over LUKS

1. **Plausible Deniability**: No headers means there's no way to prove encryption exists on the device
2. **Resilience to Corruption**: If part of the data is corrupted, only that section is affected (unlike LUKS where header corruption can make the entire volume inaccessible)
3. **Enhanced Privacy**: No signatures or markers that identify the data as being encrypted
4. **Hidden Volumes**: Using offsets, encrypted volumes can be hidden within other data
5. **Quantum Security**: Multiple encryption layers with different algorithms provide defense against future attacks that might break a single algorithm

### Offsets Explained

The offset feature allows you to start your encrypted volume at any sector of the storage medium. This enables:

- Hiding encrypted volumes after regular data or other encrypted volumes
- Creating multiple independent encrypted volumes on a single device
- Further enhancing plausible deniability by placing encrypted data in unexpected locations

### Multi-Level Security Strategy

For optimal security:
- You don't need complex passwords for every level
- Strategic placement of complex passwords at certain levels provides excellent security
- Mix different ciphers across levels to protect against algorithm-specific vulnerabilities
- Each level multiplies the work required to break the encryption

### known issues

some combinations of ciphers. keys, hashes may not work when running the script, if so, either edit that level, or go back and try again.
in general [cipher]-xts-plain64 is a good option
