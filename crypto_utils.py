#!/usr/bin/env python3

class CryptoUtils:
    # Cached cipher list to avoid re-parsing /proc/crypto every time
    _cached_ciphers = None
    
    # Default block size for ciphers (in bytes)
    _DEFAULT_BLOCKSIZE = 16
    
    # Hardcoded block sizes for known ciphers (fallback)
    _CIPHER_BLOCKSIZES = {
        # 128-bit (16-byte) block ciphers
        "aes": 16,
        "twofish": 16,
        "serpent": 16,
        "camellia": 16,
        "cast6": 16,
        "anubis": 16,
        # 64-bit (8-byte) block ciphers
        "blowfish": 8,
        "cast5": 8,
        "des": 8,
        "des3_ede": 8,
        "des3ede": 8,  # Normalized form of des3_ede (underscores removed)
    }
    
    # Known modes and their IV strategies
    _KNOWN_MODES = ["xts", "cbc", "lrw", "ecb", "ctr", "ofb", "cfb"]
    _XTS_IV = "plain64"
    _CBC_IVS = ["essiv:sha256", "plain", "plain64"]
    
    @classmethod
    def _parse_proc_crypto(cls):
        """Parse /proc/crypto to extract cipher information with block sizes."""
        try:
            with open('/proc/crypto', 'r') as f:
                content = f.read()
        except Exception:
            return {}, {}
        
        # Split into individual algorithm entries
        entries = content.split('\n\n')
        
        # Track raw block ciphers (type: cipher) with their block sizes
        raw_cipher_blocksizes = {}
        
        # Track skcipher entries
        skcipher_entries = []
        
        for entry in entries:
            if not entry.strip():
                continue
            
            lines = entry.strip().split('\n')
            entry_dict = {}
            
            for line in lines:
                if ':' in line:
                    key, value = line.split(':', 1)
                    entry_dict[key.strip()] = value.strip()
            
            entry_type = entry_dict.get('type', '')
            
            # Collect raw block cipher primitives (type: cipher)
            if entry_type == 'cipher':
                name = entry_dict.get('name', '')
                blocksize = entry_dict.get('blocksize', '')
                if name and blocksize:
                    try:
                        raw_cipher_blocksizes[name] = int(blocksize)
                    except ValueError:
                        pass
            
            # Collect skcipher entries (already mode-combined)
            elif entry_type == 'skcipher':
                skcipher_entries.append(entry_dict)
        
        return raw_cipher_blocksizes, skcipher_entries
    
    @classmethod
    def _build_cipher_strings(cls, cipher, mode, blocksize=None):
        """Build cipher strings for a given cipher, mode, and blocksize.
        
        Args:
            cipher: Base cipher name (e.g., 'aes', 'twofish')
            mode: Mode of operation (e.g., 'xts', 'cbc')
            blocksize: Block size in bytes (default uses _DEFAULT_BLOCKSIZE)
            
        Returns:
            Set of cipher strings
        """
        if blocksize is None:
            blocksize = cls._DEFAULT_BLOCKSIZE
        
        strings = set()
        if mode == "xts":
            if blocksize == 16:  # XTS requires 128-bit (16-byte) block cipher
                strings.add(f"{cipher}-xts-{cls._XTS_IV}")
        elif mode == "cbc":
            for iv in cls._CBC_IVS:
                strings.add(f"{cipher}-cbc-{iv}")
        elif mode in cls._KNOWN_MODES:
            strings.add(f"{cipher}-{mode}-plain64")
        return strings
    
    @classmethod
    def get_available_ciphers(cls):
        """Get list of available dm-crypt cipher strings from /proc/crypto.
        
        Returns a cached list on subsequent calls to avoid re-parsing.
        """
        if cls._cached_ciphers is not None:
            return list(cls._cached_ciphers)
        
        raw_cipher_blocksizes, skcipher_entries = cls._parse_proc_crypto()
        
        cipher_strings = set()
        
        # Process raw block ciphers to infer mode combinations
        for cipher, blocksize in raw_cipher_blocksizes.items():
            # Normalize cipher name
            cipher_normalized = cipher.lower().replace('_', '')
            
            # Build cipher strings for common modes
            for mode in ["xts", "cbc"]:
                cipher_strings.update(cls._build_cipher_strings(cipher_normalized, mode, blocksize))
        
        # Process skcipher entries
        for entry in skcipher_entries:
            name = entry.get('name', '')
            blocksize_str = entry.get('blocksize', '')
            
            # Try to parse blocksize
            try:
                blocksize = int(blocksize_str)
            except (ValueError, TypeError):
                blocksize = None
            
            # Check if this is a dm-crypt compatible cipher string
            # Format: cipher-mode-iv
            parts = name.split('-')
            if len(parts) >= 2:
                cipher = parts[0]
                mode = parts[1] if len(parts) > 1 else None
                
                # Determine blocksize
                if blocksize is None:
                    blocksize = cls._CIPHER_BLOCKSIZES.get(cipher, cls._DEFAULT_BLOCKSIZE)
                
                # Build cipher strings
                if mode:
                    cipher_strings.update(cls._build_cipher_strings(cipher, mode, blocksize))
        
        # Add some well-known multi-cipher combinations (if base ciphers exist)
        base_128bit = ["aes", "twofish", "serpent"]
        available_base = [c for c in base_128bit if any(c in s for s in cipher_strings)]
        
        if len(available_base) >= 2:
            # Add 2-cipher chains
            if "aes" in available_base and "twofish" in available_base:
                cipher_strings.add("aes-twofish-xts-plain64")
            if "twofish" in available_base and "serpent" in available_base:
                cipher_strings.add("twofish-serpent-xts-plain64")
            
            # Add 3-cipher chain if all three are available
            if len(available_base) >= 3:
                cipher_strings.add("aes-twofish-serpent-xts-plain64")
        
        # Sort for consistency
        cls._cached_ciphers = sorted(cipher_strings)
        return list(cls._cached_ciphers)
    
    @staticmethod
    def get_available_key_sizes(cipher):
        """Get available key sizes for a cipher with proper compatibility handling"""
        # Base key sizes supported by different ciphers (in bits)
        base_cipher_key_sizes = {
            "aes": [128, 192, 256],
            "twofish": [128, 192, 256],
            "serpent": [128, 192, 256],
            "camellia": [128, 192, 256],
            "blowfish": [128, 160, 192, 224, 256],
            "cast5": [128],
            "cast6": [128, 160, 192, 224, 256],
            "des": [64],
            "des3_ede": [192],
            "anubis": [128],
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
        """Return list of hash types known to work with cryptsetup plain mode.

        These are hardcoded because cryptsetup uses its own crypto backend
        (libgcrypt/openssl) for passphrase hashing, NOT the kernel crypto API.
        The kernel module state is irrelevant for hash availability.
        sha1 is deliberately excluded — it is cryptographically weak for
        key derivation and should not be offered as an option.
        """
        return [
            "sha512",
            "sha256",
            "sha384",
            "sha224",
            "whirlpool",
            "ripemd160",
        ]
