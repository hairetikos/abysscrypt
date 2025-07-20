# AbyssCrypt

**AbyssCrypt** is a powerful multi-level dm-crypt encryption solution with a user-friendly GUI wizard.  Create up to 108 levels of encryption on a single device or file container each with their own cipher, keysize, and hash algorithm.

![image1](https://github.com/hairetikos/abysscrypt/blob/main/abyss1.png)

![image2](https://github.com/hairetikos/abysscrypt/blob/main/abysslevels.png)


## 🔐 Features

- **Deep Encryption**: Create up to 108 nested encryption levels
- **Maximum Flexibility**: Customize cipher, key size, and hash algorithm for each level
- **Offset Support**: Hide encrypted data at custom offsets in the storage medium
- **Plain dm-crypt**: No headers, fully transparent encryption (no LUKS)
- **Quantum Resistance**: Multi-level encryption provides enhanced security against future attacks
- **Container Support**: Works with both file containers and block devices
- **Script Generation**: Automatically generates mount/unmount scripts

## 🚀 Installation & usage

install dependencies (`python3`, `qt5`)

Debian/Ubuntu/Mint  `# apt install python3 python3-qtpy-pyqt5`

Fedora/RHEL/CentOS  `# dnf install python3 python3-qt5`

Arch Linux/Manjaro  `# pacman -S python python-pyqt5`

openSUSE  `# zypper install python3 python3-qt5`

```bash
git clone https://github.com/hairetikos/abysscrypt
cd abysscrypt
sudo python abysscrypt.py
```

root is required for dm-crypt, cipher enumeration and invocations.

in general [cipher]-xts-plain64 is a good option for each level.

## 📝 Description

AbyssCrypt provides a Qt-based wizard interface for creating nested dm-crypt volumes with multiple encryption levels. Each level can have completely different encryption settings, making it extremely difficult to break through all layers of security. The application generates ready-to-use shell scripts for mounting and unmounting your encrypted volumes.

**The script may be discarded after first use, but only if you are confident that you can remember passphrases for each level, along with their ciphers, key sizes, and hashes!**

**this is not LUKS, there is NO metadata... either remember everything with mnemonic techniques, or keep the script safe.**

## ⚙️ Plain dm-crypt vs LUKS

AbyssCrypt uses plain dm-crypt mode (not LUKS) for several important security advantages:

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
