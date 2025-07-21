#!/usr/bin/env python3

import os
from PyQt5.QtWidgets import (QWizard, QWizardPage, QLabel, QVBoxLayout, 
                           QHBoxLayout, QRadioButton, QLineEdit, QPushButton,
                           QFileDialog, QSpinBox, QComboBox, QCheckBox, 
                           QGroupBox, QScrollArea, QWidget, QMessageBox,
                           QTextEdit)
from PyQt5.QtCore import Qt, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QIcon

from crypto_utils import CryptoUtils
from level_config import EncryptionLevel
from script_generator import ScriptGenerator

class IntroPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Welcome to AbyssCrypt")
        self.setSubTitle("This wizard will guide you through creating a multi-level dm-crypt encryption solution.")
        
        layout = QVBoxLayout()
        
        intro_text = QLabel(
            "AbyssCrypt allows you to create nested dm-crypt volumes with different "
            "encryption settings at each level.\n\n"
            "Features:\n"
            "• Plain dm-crypt (no LUKS)\n"
            "• Multi-level nested encryption (3-108 levels)\n"
            "• Custom cipher, key size, and hash type per level\n"
            "• Support for file containers or block devices\n"
            "• Automatic script generation for mount/unmount\n\n"
            "Click Next to get started."
        )
        intro_text.setWordWrap(True)
        
        layout.addWidget(intro_text)
        self.setLayout(layout)


class LevelCountPage(QWizardPage):
    level_count_selected = pyqtSignal(int)
    
    def __init__(self):
        super().__init__()
        self.setTitle("Configure Encryption Levels")
        self.setSubTitle("Select the number of encryption levels to use (3-108).")
        
        layout = QVBoxLayout()
        
        level_layout = QHBoxLayout()
        level_layout.addWidget(QLabel("Number of Levels:"))
        self.level_count = QSpinBox()
        self.level_count.setRange(3, 108)  # Changed from 69 to 108
        self.level_count.setValue(3)
        level_layout.addWidget(self.level_count)
        
        info_label = QLabel(
            "Each level adds an additional layer of encryption with its own settings. "
            "You'll be able to configure each level in the following steps."
        )
        info_label.setWordWrap(True)
        
        layout.addLayout(level_layout)
        layout.addWidget(info_label)
        layout.addStretch()
        
        self.setLayout(layout)
        
        # Register field
        self.registerField("level_count", self.level_count)
    
    def validatePage(self):
        # Emit signal with the selected level count when page is validated
        self.level_count_selected.emit(self.level_count.value())
        return True


class LevelConfigPage(QWizardPage):
    def __init__(self, level_num, wizard=None):
        super().__init__()
        self.level_num = level_num
        self.wizard = wizard  # Store reference to wizard for accessing previous level data
        self.setTitle(f"Level {level_num} Configuration")
        self.setSubTitle(f"Configure encryption settings for level {level_num}.")
        
        # Get available options
        self.crypto_utils = CryptoUtils()
        self.ciphers = self.crypto_utils.get_available_ciphers()
        self.hash_types = self.crypto_utils.get_available_hash_types()
        
        layout = QVBoxLayout()
        
        # Cipher selection
        cipher_layout = QHBoxLayout()
        cipher_layout.addWidget(QLabel("Cipher:"))
        self.cipher_combo = QComboBox()
        self.cipher_combo.addItems(self.ciphers)
        cipher_layout.addWidget(self.cipher_combo)
        layout.addLayout(cipher_layout)
        
        # Key size selection
        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("Key Size (bits):"))
        self.key_size_combo = QComboBox()
        # Default key sizes, will be updated when cipher changes
        self.key_size_combo.addItems([str(size) for size in [128, 256, 512]])
        key_size_layout.addWidget(self.key_size_combo)
        layout.addLayout(key_size_layout)
        
        # Hash type selection
        hash_layout = QHBoxLayout()
        hash_layout.addWidget(QLabel("Hash:"))
        self.hash_combo = QComboBox()
        self.hash_combo.addItems(self.hash_types)
        hash_layout.addWidget(self.hash_combo)
        layout.addLayout(hash_layout)
        
        # Authentication method
        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout()
        
        self.passphrase_check = QCheckBox("Use Passphrase")
        self.passphrase_check.setChecked(True)
        auth_layout.addWidget(self.passphrase_check)
        
        key_file_layout = QHBoxLayout()
        key_file_layout.addWidget(QLabel("Key File:"))
        self.keyfile_path = QLineEdit()
        self.keyfile_path.setEnabled(False)
        key_file_layout.addWidget(self.keyfile_path)
        self.keyfile_browse = QPushButton("Browse...")
        self.keyfile_browse.setEnabled(False)
        key_file_layout.addWidget(self.keyfile_browse)
        auth_layout.addLayout(key_file_layout)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Offset (for all levels - now including level 1)
        offset_group = QGroupBox("Offset")
        offset_layout = QVBoxLayout()
        
        info_label = QLabel(
            "The offset is the number of sectors to skip at the beginning of the device. "
            "This can be used to hide the presence of encrypted data."
        )
        info_label.setWordWrap(True)
        offset_layout.addWidget(info_label)
        
        offset_input_layout = QHBoxLayout()
        offset_input_layout.addWidget(QLabel("Offset (sectors):"))
        self.offset_spin = QSpinBox()
        self.offset_spin.setRange(0, 2147483647)  # Large range
        self.offset_spin.setValue(0)  # Default no offset
        offset_input_layout.addWidget(self.offset_spin)
        offset_layout.addLayout(offset_input_layout)
        
        offset_group.setLayout(offset_layout)
        layout.addWidget(offset_group)
        
        layout.addStretch()
        self.setLayout(layout)
        
        # Connect signals
        self.cipher_combo.currentTextChanged.connect(self.update_key_sizes)
        self.passphrase_check.toggled.connect(self.update_keyfile_ui)
        self.keyfile_browse.clicked.connect(self.browse_keyfile)
        
        # Initialize UI
        self.update_key_sizes(self.cipher_combo.currentText())
        
        # Register fields
        self.registerField(f"level{level_num}_cipher", self.cipher_combo, "currentText")
        self.registerField(f"level{level_num}_key_size", self.key_size_combo, "currentText")
        self.registerField(f"level{level_num}_hash", self.hash_combo, "currentText")
        self.registerField(f"level{level_num}_use_passphrase", self.passphrase_check)
        self.registerField(f"level{level_num}_keyfile", self.keyfile_path)
        # Register offset field for all levels
        self.registerField(f"level{level_num}_offset", self.offset_spin)
    
    def update_key_sizes(self, cipher):
        self.key_size_combo.clear()
        key_sizes = self.crypto_utils.get_available_key_sizes(cipher)
        self.key_size_combo.addItems([str(size) for size in key_sizes])
    
    def update_keyfile_ui(self):
        use_passphrase = self.passphrase_check.isChecked()
        self.keyfile_path.setEnabled(not use_passphrase)
        self.keyfile_browse.setEnabled(not use_passphrase)
    
    def browse_keyfile(self):
        keyfile, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "All Files (*)")
        if keyfile:
            self.keyfile_path.setText(keyfile)
            
class SummaryPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Configuration Summary")
        self.setSubTitle("Review your multi-level encryption configuration.")
        
        layout = QVBoxLayout()
        
        # Create scrollable area for summary
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        self.summary_layout = QVBoxLayout(scroll_content)
        
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        
        self.setLayout(layout)
    
    def initializePage(self):
        # Clear previous summary
        while self.summary_layout.count():
            item = self.summary_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
        
        # Level info
        level_count = self.field("level_count")
        
        # Add a note about the container being specified at runtime
        container_title = QLabel("<b>Container Information:</b>")
        container_info = QLabel("The container file or device will be specified when you run the script.")
        container_info.setWordWrap(True)
        
        self.summary_layout.addWidget(container_title)
        self.summary_layout.addWidget(container_info)
        self.summary_layout.addWidget(QLabel("<hr>"))
        
        for i in range(1, level_count + 1):
            level_title = QLabel(f"<b>Level {i} Configuration:</b>")
            
            cipher = self.field(f"level{i}_cipher")
            key_size = self.field(f"level{i}_key_size")
            hash_type = self.field(f"level{i}_hash")
            use_passphrase = self.field(f"level{i}_use_passphrase")
            keyfile = self.field(f"level{i}_keyfile") if not use_passphrase else "N/A"
            offset = self.field(f"level{i}_offset")  # Now all levels have offset
            
            auth_method = "Passphrase" if use_passphrase else f"Keyfile: {keyfile}"
            
            level_info = QLabel(
                f"Cipher: {cipher}\n"
                f"Key Size: {key_size} bits\n"
                f"Hash: {hash_type}\n"
                f"Authentication: {auth_method}\n"
                f"Offset: {offset} sectors"  # Always show offset
            )
            
            self.summary_layout.addWidget(level_title)
            self.summary_layout.addWidget(level_info)
            
            if i < level_count:
                self.summary_layout.addWidget(QLabel("<hr>"))
        
        self.summary_layout.addStretch()


class FinalPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Generated Scripts")
        self.setSubTitle("Your multi-level encryption scripts have been generated.")
        
        layout = QVBoxLayout()
        
        info_label = QLabel(
            "The wizard has generated mount and unmount scripts based on your configuration. "
            "The scripts will prompt you for the container file or device path when executed, "
            "enhancing security by not storing the path in the script."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Script display area
        scripts_group = QGroupBox("Mount Script")
        scripts_layout = QVBoxLayout()
        
        self.script_text = QTextEdit()
        self.script_text.setReadOnly(True)
        self.script_text.setLineWrapMode(QTextEdit.NoWrap)
        self.script_text.setFont(QFont("Courier", 10))
        scripts_layout.addWidget(self.script_text)
        
        scripts_group.setLayout(scripts_layout)
        layout.addWidget(scripts_group)
        
        # Save buttons
        buttons_layout = QHBoxLayout()
        
        self.save_mount_button = QPushButton("Save Mount Script...")
        self.save_unmount_button = QPushButton("Save Unmount Script...")
        
        buttons_layout.addWidget(self.save_mount_button)
        buttons_layout.addWidget(self.save_unmount_button)
        
        layout.addLayout(buttons_layout)
        
        self.setLayout(layout)
        
        # Connect signals
        self.save_mount_button.clicked.connect(self.save_mount_script)
        self.save_unmount_button.clicked.connect(self.save_unmount_script)
        
        # Store generated scripts
        self.mount_script = ""
        self.unmount_script = ""
    
    def initializePage(self):
        # Create the encryption levels from wizard data
        level_count = self.field("level_count")
        levels = []
        
        for i in range(1, level_count + 1):
            level = EncryptionLevel(i)
            level.cipher = self.field(f"level{i}_cipher")
            level.key_size = int(self.field(f"level{i}_key_size"))
            level.hash_type = self.field(f"level{i}_hash")
            level.use_passphrase = self.field(f"level{i}_use_passphrase")
            if not level.use_passphrase:
                level.keyfile_path = self.field(f"level{i}_keyfile")
            # Always get offset for all levels
            level.offset = int(self.field(f"level{i}_offset"))
            
            levels.append(level)
        
        # Generate scripts with prompt for container
        script_gen = ScriptGenerator("prompt", "", levels)
        self.mount_script = script_gen.generate_mount_script()
        self.unmount_script = script_gen.generate_unmount_script()
        
        # Display mount script in text area
        self.script_text.setText(self.mount_script)
    
    def save_mount_script(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Mount Script", "", "Shell Scripts (*.sh);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.mount_script)
                os.chmod(file_path, 0o755)  # Make executable
                QMessageBox.information(self, "Success", f"Mount script saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save mount script: {str(e)}")
    
    def save_unmount_script(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Unmount Script", "", "Shell Scripts (*.sh);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.unmount_script)
                os.chmod(file_path, 0o755)  # Make executable
                QMessageBox.information(self, "Success", f"Unmount script saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save unmount script: {str(e)}")


class AbyssCryptWizard(QWizard):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("AbyssCrypt Wizard")
        self.setMinimumSize(QSize(700, 600))  # Made taller to fit the script display
        
        # Set wizard style
        self.setWizardStyle(QWizard.ModernStyle)
        
        # Define the main pages
        self.intro_page = IntroPage()
        self.level_count_page = LevelCountPage()
        self.summary_page = SummaryPage()
        self.final_page = FinalPage()
        
        # Add fixed pages
        self.addPage(self.intro_page)
        self.addPage(self.level_count_page)
        
        # Store info about level pages
        self.level_pages = []
        self.level_count = 3  # Default
        
        # Connect signal to update level count and create level pages
        self.level_count_page.level_count_selected.connect(self.create_level_pages)
        
        # Add the summary and final pages
        self.addPage(self.summary_page)
        self.addPage(self.final_page)
    
    def create_level_pages(self, count):
        """Create or recreate the level configuration pages based on the count"""
        self.level_count = count
        
        # Remove existing level pages if any
        for page in self.level_pages:
            page_id = self.pageIds()[self.pageIds().index(self.currentId()) + 1]
            self.removePage(page_id)
        
        # Clear the list of level pages
        self.level_pages.clear()
        
        # We need to remove the summary and final pages to insert level pages before them
        summary_id = self.pageIds()[self.pageIds().index(self.currentId()) + 1]
        final_id = self.pageIds()[self.pageIds().index(self.currentId()) + 2]
        
        self.removePage(final_id)
        self.removePage(summary_id)
        
        # Create and add new level pages
        for i in range(1, count + 1):
            level_page = LevelConfigPage(i, wizard=self)  # Pass self as wizard reference
            self.level_pages.append(level_page)
            self.addPage(level_page)
        
        # Add summary and final pages back
        self.addPage(self.summary_page)
        self.addPage(self.final_page)
