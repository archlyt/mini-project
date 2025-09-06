
import os
import zipfile
import re
import shutil
import hashlib
import json
from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup

MALWARE_SIG_FILE = "malware_signatures.json"
PHISHING_DB = "phishing_blacklist.json"
MITIGATION_FILE = "mitigation_guide.txt"

def get_all_files(base_path="/storage/emulated/0"):
    for root, _, files in os.walk(base_path):
        for file in files:
            yield os.path.join(root, file)

def compute_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except:
        return None

def load_signatures():
    try:
        with open(MALWARE_SIG_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def load_phishing_db():
    try:
        with open(PHISHING_DB, "r") as f:
            return json.load(f)
    except:
        return []

def load_mitigation():
    try:
        with open(MITIGATION_FILE, "r") as f:
            return f.read()
    except:
        return "No mitigation steps found."

def quarantine(file_path):
    os.makedirs("quarantine", exist_ok=True)
    try:
        shutil.move(file_path, os.path.join("quarantine", os.path.basename(file_path)))
    except:
        pass

def detect_malicious_apk(file_path, signatures):
    try:
        if not zipfile.is_zipfile(file_path):
            return False, ""
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            if "AndroidManifest.xml" in zip_ref.namelist():
                for name in zip_ref.namelist():
                    if name.endswith(".xml") or name.endswith(".dex"):
                        with zip_ref.open(name) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            for sig in signatures.get("apk_permissions", []):
                                if sig.lower() in content.lower():
                                    return True, f"Matched: {sig}"
        hash_val = compute_hash(file_path)
        if hash_val and hash_val in signatures.get("hashes", []):
            return True, f"Matched hash: {hash_val}"
    except:
        pass
    return False, ""

def contains_phishing_link(file_path, phishing_list):
    try:
        with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # Extract all URLs from the content
            urls = re.findall(r'https?://[^\s"\']+', content)
            
            # Check if any URL contains a known phishing domain or string
            for url in urls:
                for bad in phishing_list:
                    if bad in url:
                        return True, url  # Return True and the matched URL
            
            # No phishing links found
            return False, None
    except Exception as e:
        print(f"Error reading file: {e}")
        return False, None

class MalwareScannerApp(App):
    def build(self):
        layout = BoxLayout(orientation='vertical', spacing=10, padding=10)
        self.label = Label(text="Malware & Phishing Scanner Ready.", size_hint_y=None, height=50)
        btn_scan = Button(text="Scan Storage", on_press=self.run_scan)
        layout.add_widget(self.label)
        layout.add_widget(btn_scan)
        self.results = Label(text="", size_hint_y=None)
        scroll = ScrollView()
        scroll.add_widget(self.results)
        layout.add_widget(scroll)
        return layout

    def run_scan(self, instance):
        self.label.text = "Scanning..."
        results = ""
        signatures = load_signatures()
        phishing_db = load_phishing_db()
        for file in get_all_files("/storage/emulated/0"):
            if file.endswith(".apk"):
                detected, reason = detect_malicious_apk(file, signatures)
                if detected:
                    quarantine(file)
                    results += f"[APK] {file}\n-> {reason}\n"
            elif file.endswith((".txt", ".html", ".json", ".xml")):
                detected, url = contains_phishing_link(file, phishing_db)
                if detected:
                    quarantine(file)
                    results += f"[Phishing] {file}\n-> Suspicious URL: {url}\n"

        if results == "":
            results = "No threats found."
        else:
            results += "\nMitigation:\n" + load_mitigation()
        self.results.text = results
        self.label.text = "Scan complete."

if __name__ == '__main__':
    MalwareScannerApp().run()
