import time
import os
import hashlib
import winsound
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# =========================
# Utility Functions
# =========================

def write_log(message):
    os.makedirs("logs", exist_ok=True)
    with open("logs/activity_log.txt", "a") as log:
        log.write(f"[{datetime.now()}] {message}\n")


def calculate_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except:
        return None


def load_sensitive_files():
    try:
        with open("sensitive_files.txt", "r") as f:
            return [line.strip() for line in f.readlines()]
    except:
        return []


def is_usb_path(path):
    return path.startswith("E:\\")


# =========================
# Global Variables
# =========================

file_hashes = {}
sensitive_files = load_sensitive_files()
transfer_count = 0


# =========================
# File System Handler
# =========================

class MyHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            print(f"File created: {event.src_path}")
            write_log(f"File created: {event.src_path}")
            file_hashes[event.src_path] = calculate_hash(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            file_path = event.src_path
            new_hash = calculate_hash(file_path)
            old_hash = file_hashes.get(file_path)

            if old_hash and new_hash and new_hash != old_hash:
                print("[ALERT] Integrity violation detected!")
                print("Modified file:", file_path)
                write_log(f"Integrity violation detected: {file_path}")

            file_hashes[file_path] = new_hash

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"File deleted: {event.src_path}")
            write_log(f"File deleted: {event.src_path}")

    def on_moved(self, event):
        global transfer_count

        if not event.is_directory:
            src = event.src_path
            dest = event.dest_path

            print(f"File moved from {src} to {dest}")
            write_log(f"File moved from {src} to {dest}")

            # Bulk Transfer Detection
            transfer_count += 1
            if transfer_count > 2:  # test ke liye small number
                print("[ALERT] Suspicious bulk transfer detected!")
                write_log("ALERT: Suspicious bulk transfer detected")
                transfer_count = 0

            # USB + Sensitive File Detection
            if src in sensitive_files and is_usb_path(dest):
                print("[CRITICAL ALERT] Sensitive file moved to USB!")
                write_log(f"CRITICAL: Sensitive file moved to USB: {src} → {dest}")


def generate_report():
    created = 0
    deleted = 0
    integrity_alerts = 0
    usb_alerts = 0
    bulk_alerts = 0

    try:
        with open("logs/activity_log.txt", "r") as log:
            lines = log.readlines()

        for line in lines:
            if "File created" in line:
                created += 1
            if "File deleted" in line:
                deleted += 1
            if "Integrity violation" in line:
                integrity_alerts += 1
            if "CRITICAL" in line:
                usb_alerts += 1
            if "bulk transfer" in line.lower():
                bulk_alerts += 1

        os.makedirs("reports", exist_ok=True)
        with open("reports/final_report.txt", "w") as report:
            report.write("=== FINAL AUDIT REPORT ===\n\n")
            report.write(f"Total Files Created: {created}\n")
            report.write(f"Total Files Deleted: {deleted}\n")
            report.write(f"Total Integrity Alerts: {integrity_alerts}\n")
            report.write(f"Total USB Critical Alerts: {usb_alerts}\n")
            report.write(f"Total Bulk Transfer Alerts: {bulk_alerts}\n")

        print("Final audit report generated successfully!")

    except FileNotFoundError:
        print("Log file not found. No report generated.")


# =========================
# Main
# =========================

if __name__ == "__main__":
    path = "."
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    print("Monitoring started...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        generate_report()

    observer.join()