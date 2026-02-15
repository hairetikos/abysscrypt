#!/usr/bin/env python3

import re

class CryptoUtils:
    _cached_ciphers = None
    _cached_hash_types = None
    _XTS_IV = "plain64"
    _CBC_IVS = ["plain64", "essiv:sha256"]
    _KNOWN_MODES = {"xts", "cbc", "ecb", "ctr", "cfb", "ofb"}

    _KNOWN_CASCADES = [
        ("aes-twofish-xts-plain64", ["aes", "twofish"]),
        ("twofish-serpent-xts-plain64", ["twofish", "serpent"]),
        ("aes-twofish-serpent-xts-plain64", ["aes", "twofish", "serpent"]),
    ]

    _FALLBACK_CIPHERS = [
        "aes-xts-plain64",
        "aes-cbc-essiv:sha256",
        "twofish-xts-plain64",
        "serpent-xts-plain64",
        "camellia-xts-plain64",
    ]

    _FALLBACK_HASHES = [
        "sha1", "sha256", "sha512", "ripemd160", "whirlpool",
    ]

    @staticmethod
    def _parse_proc_crypto():
        """Parse /proc/crypto and return list of algorithm entries"""
        try:
            with open("/proc/crypto", "r") as fh:
                content = fh.read()
        except OSError:
            return []

        entries = []
        for block in content.split("\n\n"):
            entry = {}
            for line in block.strip().splitlines():
                m = re.match(r"(\w+)\s*:\s*(.+)", line.strip())
                if m:
                    entry[m.group(1).strip()] = m.group(2).strip()
            if entry:
                entries.append(entry)
        return entries

    @classmethod
    def _build_cipher_strings(cls, cipher, mode):
        """Build dm-crypt cipher strings for a given cipher and mode"""
        result = set()
        if mode == "xts":
            result.add(f"{cipher}-xts-{cls._XTS_IV}")
        elif mode == "cbc":
            for iv in cls._CBC_IVS:
                result.add(f"{cipher}-cbc-{iv}")
        elif mode in cls._KNOWN_MODES:
            result.add(f"{cipher}-{mode}-{cls._XTS_IV}")
        return result

    @classmethod
    def get_available_ciphers(cls):
        """Get all available ciphers from /proc/crypto"""
        # Check cache first
        if cls._cached_ciphers is not None:
            return list(cls._cached_ciphers)

        entries = cls._parse_proc_crypto()
        if not entries:
            cls._cached_ciphers = cls._FALLBACK_CIPHERS.copy()
            return list(cls._cached_ciphers)

        raw_block_ciphers = set()
        available_mode_wrappers = set()
        cipher_strings = set()

        # Process all entries
        for entry in entries:
            entry_type = entry.get("type", "")
            name = entry.get("name", "")

            # Process skcipher entries (pre-assembled cipher+mode combinations)
            if entry_type == "skcipher":
                # Match kernel notation: xts(aes), cbc(serpent), etc.
                m = re.match(r"^(\w+)\((\w+)\)$", name)
                if m:
                    mode = m.group(1)
                    cipher = m.group(2)
                    if mode in cls._KNOWN_MODES:
                        available_mode_wrappers.add(mode)
                        cipher_strings.update(cls._build_cipher_strings(cipher, mode))

            # Process cipher entries (raw block cipher primitives)
            elif entry_type == "cipher":
                if re.match(r"^[a-z][a-z0-9_]*$", name):
                    raw_block_ciphers.add(name)

        # Infer additional combinations from raw ciphers and available modes
        for cipher in raw_block_ciphers:
            for mode in available_mode_wrappers & cls._KNOWN_MODES:
                cipher_strings.update(cls._build_cipher_strings(cipher, mode))

        # Add well-known cascades if all constituent primitives exist
        for cascade_str, required_primitives in cls._KNOWN_CASCADES:
            if all(prim in raw_block_ciphers for prim in required_primitives):
                cipher_strings.add(cascade_str)

        result = sorted(cipher_strings)
        cls._cached_ciphers = result.copy()
        return result

    @staticmethod
    def get_available_key_sizes(cipher):
        """Get available key sizes for a cipher with proper compatibility handling"""
        # Base key sizes supported by different ciphers (in bits)
        base_cipher_key_sizes = {
            "aes": [128, 192, 256],  # AES standard key sizes
            "twofish": [128, 192, 256],  # Twofish key sizes
            "serpent": [128, 192, 256],  # Serpent key sizes
            "camellia": [128, 192, 256],  # Camellia key sizes
            "anubis": [128, 160, 192, 224, 256, 288, 320],  # Anubis key sizes
            "blowfish": [128, 160, 192, 224, 256],  # Blowfish can support various sizes
            "cast5": [128],  # CAST5 supports 128-bit
            "cast6": [128, 160, 192, 224, 256],  # CAST6 supports multiple sizes
            "des": [64],  # DES is 64-bit (with 56 bits actually used)
            "des3_ede": [192],  # Triple DES uses 192 bits (168 bits effective)
        }
        
        # Parse the cipher string
        parts = cipher.lower().split('-')
        
        # Handle special case for XTS mode
        if "xts" in parts:
            # In XTS mode, the key size is double the cipher's base key size
            # Extract the main cipher(s)
            main_ciphers = [p for p in parts if p not in ["xts", "plain", "plain64", "essiv:sha256"]]
            
            # Check for multi-cipher chains
            if len(main_ciphers) > 1:
                # For multi-cipher chains in XTS mode, use conservative approach
                # Each cipher gets its own key
                supported_sizes = []
                for size in [256, 512]:  # Only 256 and 512 are safe for XTS chains
                    key_per_cipher = size // len(main_ciphers)
                    # Only include if each cipher gets a standard key size
                    valid = all(key_per_cipher // 2 in base_cipher_key_sizes.get(c, []) 
                               for c in main_ciphers)
                    if valid:
                        supported_sizes.append(size)
                return supported_sizes
            else:
                # Single cipher in XTS mode
                main_cipher = main_ciphers[0]
                # Get base sizes for this cipher
                base_sizes = base_cipher_key_sizes.get(main_cipher, [128, 256])
                # In XTS mode, the key is split in two (half for encryption, half for tweak)
                # So we double each base size to get the actual key size needed
                return [size * 2 for size in base_sizes]
        
        # Handle CBC and other non-XTS modes
        elif "cbc" in parts or any(p in parts for p in ["ecb", "cfb", "ofb", "ctr"]):
            main_ciphers = [p for p in parts if p not in ["cbc", "ecb", "cfb", "ofb", "ctr", 
                                                         "plain", "plain64", "essiv:sha256"]]
            
            # For multi-cipher chains
            if len(main_ciphers) > 1:
                # Each cipher needs its own key
                supported_sizes = []
                for size in [128, 192, 256]:
                    # Multiply by number of ciphers in chain
                    chain_size = size * len(main_ciphers)
                    supported_sizes.append(chain_size)
                return supported_sizes
            else:
                # Single cipher
                main_cipher = main_ciphers[0]
                return base_cipher_key_sizes.get(main_cipher, [128, 192, 256])
        
        # If we can't determine mode or it's a custom format, use a safe default
        else:
            # Check if it's a recognized cipher
            for cipher_name in base_cipher_key_sizes:
                if cipher_name in cipher:
                    return base_cipher_key_sizes[cipher_name]
            
            # Default fallback
            return [128, 192, 256]

    @classmethod
    def get_available_hash_types(cls):
        """Get available hash types from /proc/crypto"""
        # Check cache first
        if cls._cached_hash_types is not None:
            return list(cls._cached_hash_types)

        entries = cls._parse_proc_crypto()
        if not entries:
            cls._cached_hash_types = cls._FALLBACK_HASHES.copy()
            return list(cls._cached_hash_types)

        hash_types = set()
        valid_prefixes = ("sha", "ripemd", "whirlpool", "blake2", "sm3", "md4", "md5", "streebog")

        for entry in entries:
            entry_type = entry.get("type", "")
            name = entry.get("name", "")

            # Only hash algorithms (shash = sync hash, ahash = async hash)
            if entry_type in ("shash", "ahash"):
                # Only keep simple names matching pattern (excludes hmac(sha256), cmac(aes), etc.)
                if re.match(r"^[a-z][a-z0-9_-]*$", name):
                    # Filter to cryptographic hashes only
                    if name.startswith(valid_prefixes):
                        hash_types.add(name)

        result = sorted(hash_types)
        cls._cached_hash_types = result.copy()
        return result
