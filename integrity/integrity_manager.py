import hashlib
import json
import os
from datetime import datetime


class IntegrityManager:
    def __init__(self, custody_file="integrity/chain_of_custody.json"):
        self.custody_file = custody_file

        # Create custody file if it doesn't exist
        if not os.path.exists(self.custody_file):
            with open(self.custody_file, "w") as f:
                json.dump([], f, indent=4)

    def generate_hash(self, file_path):
        """
        Generates SHA-256 hash of a file
        """
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                sha256.update(block)

        return sha256.hexdigest()

    def log_event(self, file_name, file_hash, action):
        """
        Records an event in the chain-of-custody
        """
        event = {
            "file_name": file_name,
            "hash": file_hash,
            "action": action,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        # Ensure custody file exists
        if not os.path.exists(self.custody_file):
            with open(self.custody_file, "w") as f:
                json.dump([], f)

        with open(self.custody_file, "r") as f:
            custody_log = json.load(f)

        custody_log.append(event)

        with open(self.custody_file, "w") as f:
            json.dump(custody_log, f, indent=4)

    def lock_evidence(self, file_path):
        """
        Locks evidence by hashing and logging the upload
        """
        file_hash = self.generate_hash(file_path)
        file_name = os.path.basename(file_path)

        self.log_event(file_name, file_hash, "EVIDENCE_UPLOADED")

        return file_hash

    def verify_integrity(self, file_path):
        """
        Verifies if the file has been modified
        """

        # If custody file does not exist, handle safely (Demo Mode case)
        if not os.path.exists(self.custody_file):
            return False, "No chain-of-custody record found."

        current_hash = self.generate_hash(file_path)
        file_name = os.path.basename(file_path)

        with open(self.custody_file, "r") as f:
            custody_log = json.load(f)

        original_records = [
            entry for entry in custody_log
            if entry["file_name"] == file_name
        ]

        if not original_records:
            return False, "No prior custody record found."

        original_hash = original_records[0]["hash"]

        if current_hash == original_hash:
            self.log_event(file_name, current_hash, "INTEGRITY_VERIFIED")
            return True, "Evidence integrity preserved."
        else:
            self.log_event(file_name, current_hash, "INTEGRITY_FAILED")
            return False, "Evidence has been modified!"


