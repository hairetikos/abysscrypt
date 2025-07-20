#!/usr/bin/env python3

import subprocess
import re
import os

class CryptoUtils:
    @staticmethod
    def get_available_ciphers():
        """Get all available ciphers from /proc/crypto"""
        try:
            with open('/proc/crypto', 'r') as f:
                content = f.read()
                
            ciphers = set()
            for block in content.split('\n\n'):
                if 'type' in block and 'name' in block:
                    # Extract name and type
                    name_match = re.search(r'name\s*:\s*(\S+)', block)
                    type_match = re.search(r'type\s*:\s*(\S+)', block)
                    
                    if name_match and type_match:
                        name = name_match.group(1)
                        type_val = type_match.group(1)
                        
                        # Only include block ciphers
                        if type_val == "cipher":
                            ciphers.add(name)
            
            # Add common ciphers if not found
            common_ciphers = [
                "aes-xts-plain64", "aes-cbc-essiv:sha256", "aes-cbc-plain", 
                "twofish-cbc-plain", "serpent-cbc-plain", "twofish-xts-plain64",
                "serpent-xts-plain64", "aes-twofish-xts-plain64", 
                "twofish-serpent-xts-plain64", "aes-twofish-serpent-xts-plain64",
                "camellia-xts-plain64", "camellia-cbc-essiv:sha256"
            ]
            
            for cipher in common_ciphers:
                if cipher not in ciphers:
                    ciphers.add(cipher)
                    
            return sorted(list(ciphers))
        except Exception as e:
            print(f"Error getting available ciphers: {e}")
            # Return some common defaults if we can't read /proc/crypto
            return [
                "aes-xts-plain64", "aes-cbc-essiv:sha256", 
                "twofish-xts-plain64", "serpent-xts-plain64",
                "camellia-xts-plain64", "aes-twofish-serpent-xts-plain64"
            ]

    @staticmethod
    def get_available_key_sizes(cipher):
        """Get available key sizes for a cipher with proper compatibility handling"""
        # Base key sizes supported by different ciphers (in bits)
        base_cipher_key_sizes = {
            "aes": [128, 192, 256],  # AES standard key sizes
            "twofish": [128, 192, 256],  # Twofish key sizes
            "serpent": [128, 192, 256],  # Serpent key sizes
            "camellia": [128, 192, 256],  # Camellia key sizes
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

    @staticmethod
    def get_available_hash_types():
        """Get available hash types"""
        try:
            # Try getting hash types from cryptsetup
            result = subprocess.run(['cryptsetup', 'benchmarks'], 
                                    capture_output=True, text=True)
            output = result.stdout
            
            # Extract hash types
            hash_section = re.search(r'#\s+Algorithm\s+|\s+Hash[\s\S]+?(?=\n\n)', output)
            if hash_section:
                hash_text = hash_section.group(0)
                # Expanded pattern to catch more hash types
                hash_types = re.findall(r'\b(sha\d+|ripemd160|whirlpool|sm3|blake2[bs]|sha3-\d+)\b', hash_text.lower())
                if hash_types:
                    return sorted(set(hash_types))
            
            # If we can't find hash types in cryptsetup, try running openssl list
            try:
                result = subprocess.run(['openssl', 'list', '-digest-algorithms'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    output = result.stdout
                    # Extract hash names, filter out non-crypto hashes
                    hash_types = set()
                    for line in output.split('\n'):
                        if line and '=>' not in line and line.strip().lower() not in ['ssl3-md5', 'ssl3-sha1']:
                            hash_name = line.strip().lower()
                            # Only add if it's likely a crypto hash
                            if any(x in hash_name for x in ['sha', 'md', 'ripemd', 'whirl', 'blake', 'sm3']):
                                hash_types.add(hash_name)
                    
                    if hash_types:
                        return sorted(hash_types)
            except:
                pass
                
            # Default hash types if we can't extract them
            return ["sha1", "sha256", "sha512", "ripemd160", "whirlpool", "sha3-256", "sm3", "blake2b"]
        except Exception as e:
            print(f"Error getting available hash types: {e}")
            return ["sha1", "sha256", "sha512", "ripemd160", "whirlpool"]
    
    @staticmethod
    def verify_device(device_path):
        """Verify if a device exists and is a block device"""
        return os.path.exists(device_path) and os.path.isblock(device_path)
    
    @staticmethod
    def create_empty_file(file_path, size_mb):
        """Create an empty file of specified size (in MB)"""
        try:
            with open(file_path, 'wb') as f:
                f.seek(int(size_mb) * 1024 * 1024 - 1)
                f.write(b'\0')
            return True
        except Exception as e:
            print(f"Error creating empty file: {e}")
            return False