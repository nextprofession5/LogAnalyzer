from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)  # Allows your Bolt app to talk to this server safely

# Known safe software signatures to aggressively clear out false positives
WHITELIST = [
    'microsoft corporation', 'microsoft windows', 'nvidia corporation', 
    'realtek', 'valve corporation', 'epic games', 'steamapps', 
    'tiktok live studio', 'overwolf', 'discord', 'google llc'
]

@app.route('/parse', methods=['POST'])
def handle_log_triage():
    payload = request.get_json()
    raw_log = payload.get("log", "")
    lines = raw_log.split('\n')

    attention_bucket = []
    suspect_bucket = []

    for line in lines:
        clean_line = line.strip()
        lower_line = clean_line.lower()
        if not lower_line:
            continue

        # BUCKET 1: Catch ALL lines containing "ATTENTION"
        if "attention" in lower_line:
            attention_bucket.append(clean_line)
            continue

        # BUCKET 2: Advanced Expert Matcher (Excludes "No File" and "ATTENTION")
        if "no file" not in lower_line:
            if match_expert_heuristics(lower_line):
                suspect_bucket.append(clean_line)

    return jsonify({
        "system_flags": "\n".join(attention_bucket),
        "expert_suspects": "\n".join(suspect_bucket)
    })

def match_expert_heuristics(lower_line):
    # 0. Suppress verified publisher noise
    if any(item in lower_line for item in WHITELIST):
        return False

    # 1. SYSTEM MASQUERADING (Extremely High Risk)
    # Catches svchost, explorer, lsass, etc. running from Temp, AppData, or ProgramData
    if re.search(r"\\(appdata|temp|programdata|users\\[^\\]+)\\.*(svchost|explorer|csrss|lsass|smss|winlogon)\.exe", lower_line):
        return True

    # 2. MICRO-EXECUTABLES (Droppers)
    # Catches 1 or 2 character executables (e.g., \a.exe, \BB.exe, \1.exe)
    if re.search(r"\\[a-z0-9]{1,2}\.exe", lower_line):
        return True

    # 3. DOUBLE EXTENSION SPOOFING
    # Catches fake documents/images (e.g., .pdf.exe, .jpg.scr, .txt.vbs)
    if re.search(r"\.(pdf|jpg|png|doc|docx|txt|xls|mp3|mp4)\.(exe|vbs|bat|cmd|scr|pif|js)", lower_line):
        return True

    # 4. ADVANCED ADS (Alternate Data Streams)
    # Flags streams, but specifically targets executables hidden inside streams
    if lower_line.startswith("alternatedatastreams:"):
        if "zone.identifier" not in lower_line:
            return True
        if re.search(r":.*(exe|vbs|bat|ps1|dll)", lower_line): 
            return True

    # 5. HEADLESS & OBFUSCATED SHELLS
    if "conhost.exe --headless" in lower_line or re.search(r"powershell\.exe\s+-(nop|nopr|executionpolicy|ep|w\s+hidden|enc)", lower_line):
        return True

    # 6. ROGUE USER STARTUP LINKS
    if "\\start menu\\programs\\startup\\" in lower_line and ".lnk" in lower_line:
        return True

    # 7. HIGH ENTROPY FOLDERS (Randomized AppData paths)
    if "\\appdata\\local\\" in lower_line and re.search(r"\\[a-f0-9]{16,40}$", lower_line):
        return True
        
    # 8. OBSCURE MALWARE FAMILIES & TOOLS
    malware_keywords = ['vlmcsd', 'hacktool', 'miner', 'kmsauto', 'kms-rtd', 'winring0', 'psexec']
    if any(kw in lower_line for kw in malware_keywords):
        return True

    return False

if __name__ == '__main__':
    app.run(port=5000)
  
