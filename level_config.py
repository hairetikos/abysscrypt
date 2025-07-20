#!/usr/bin/env python3

class EncryptionLevel:
    def __init__(self, level_num):
        self.level_num = level_num
        self.cipher = "aes-xts-plain64"
        self.key_size = 256
        self.hash_type = "sha256"
        self.use_passphrase = True
        self.keyfile_path = ""
        self.offset = 0  # Offset in sectors (default is 0)
        
    def __str__(self):
        auth_method = "Passphrase" if self.use_passphrase else f"Keyfile: {self.keyfile_path}"
        return (f"Level {self.level_num}: {self.cipher}, Key Size: {self.key_size}, "
                f"Hash: {self.hash_type}, Auth: {auth_method}, Offset: {self.offset}")