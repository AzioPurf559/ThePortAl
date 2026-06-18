from pathlib import Path
from datetime import datetime

# ----------------------------
# CONFIG
# ----------------------------

must_check = {
    # Windows executables and scripts.
    ".exe",
    ".scr",
    ".dll",
    ".sys",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".lnk",
    ".reg",
    # Office and document formats that can hide macros or scripts.
    ".docm",
    ".xlsm",
    ".pptm",
    ".rtf",
    ".one",
    ".iso",
    ".img",
    # Archives and double-extension bait often used for delivery.
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".txt",
}

stages = {
    "execution": [
        "powershell",
        "pwsh",
        "cmd.exe",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "wmic",
        "msiexec",
        "installutil",
        "bitsadmin",
        "certutil",
        "start-process",
        "shell.application",
        "createobject",
    ],
    "network": [
        "http://",
        "https://",
        "ftp://",
        "invoke-webrequest",
        "iwr ",
        "invoke-restmethod",
        "downloadstring",
        "downloadfile",
        "webclient",
        "xmlhttp",
        "winhttprequest",
        "curl ",
        "wget ",
        "socket",
        "tcpclient",
        "net.webrequest",
    ],
    "obfuscation": [
        "base64",
        "encodedcommand",
        "-enc",
        "frombase64string",
        "iex",
        "invoke-expression",
        "char",
        "replace(",
        "split(",
        "join(",
        "xor",
        "gzipstream",
        "deflatestream",
        "hidden",
        "bypass",
        "unrestricted",
        "windowstyle hidden",
        "nop",
        "noninteractive",
    ],
    "persistence": [
        "schtasks",
        "at.exe",
        "reg add",
        "runonce",
        "currentversion\\run",
        "startup",
        "startupfolder",
        "new-service",
        "sc.exe create",
        "wmiprvse",
        "__eventfilter",
        "commandlineeventconsumer",
        "scheduledtask",
        "logon script",
        "profile.ps1",
    ],
    "credential_access": [
        "mimikatz",
        "sekurlsa",
        "lsass",
        "procdump",
        "sam",
        "ntds.dit",
        "dpapi",
        "credential",
        "password",
        "token",
        "cookies",
        "keylogger",
        "get-keystrokes",
        "clipboard",
    ],
    "discovery": [
        "whoami",
        "hostname",
        "ipconfig",
        "net user",
        "net group",
        "net localgroup",
        "nltest",
        "dsquery",
        "quser",
        "systeminfo",
        "tasklist",
        "arp -a",
        "route print",
    ],
    "defense_evasion": [
        "amsi",
        "amsiutils",
        "etw",
        "set-mppreference",
        "disableantispyware",
        "exclusionpath",
        "defender",
        "firewall",
        "wevtutil cl",
        "clear-eventlog",
        "delete shadows",
        "vssadmin",
        "takeown",
        "icacls",
    ],
    "lateral_movement": [
        "psexec",
        "winrm",
        "enter-pssession",
        "invoke-command",
        "new-pssession",
        "wmic /node",
        "net use",
        "admin$",
        "c$",
        "remote registry",
    ],
    "collection_exfiltration": [
        "compress-archive",
        "makecab",
        "tar ",
        "7z ",
        "rar ",
        "uploadfile",
        "putty",
        "pscp",
        "sftp",
        "scp ",
        "telegram",
        "discord",
        "webhook",
        "pastebin",
    ],
}

# ----------------------------
# CORE SCANNER
# ----------------------------

def scan_content(content):
    score = 0
    findings = []

    lines = content.lower().split("\n")

    for line_num, line in enumerate(lines, start=1):
        for stage, indicators in stages.items():
            for indicator in indicators:
                if indicator.lower() in line:
                    findings.append((stage, indicator, line_num))
                    score += 1

    return score, findings


# ----------------------------
# FILE ANALYZER
# ----------------------------

def examine_file(file_path):
    file_path = Path(file_path)

    if file_path.suffix.lower() not in must_check:
        print(f"{file_path} does not require examination.")
        return

    print(f"\nExamining {file_path} for potential threats...\n")

    # ---- metadata ----
    stats = file_path.stat()

    print("Name:", file_path.name)
    print("Size:", stats.st_size, "bytes")
    print("Created:", datetime.fromtimestamp(stats.st_ctime))
    print("Modified:", datetime.fromtimestamp(stats.st_mtime))
    print("Extension:", file_path.suffix)
    print("Full Path:", file_path.resolve())

    # ---- content scan ----
    print("\nMore detailed scan...\n")

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read(500)

    score, findings = scan_content(content)

    for stage, indicator, line_num in findings:
        print(f"[{stage}] Indicator found: {indicator}")
        print(f"Found at line: {line_num}\n")

#    print("\nContent Preview:")
#    print(content)

    print("\nRisk Score:", score)


# ----------------------------
# RUN EXAMPLE
# ----------------------------

examine_file("C:\\Users\\axelg\\Desktop\\ThePortAl\\tuff.exe")