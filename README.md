# Andro-Deep-Link-Inquisitor 📱🔍

**Andro-Deep-Link-Inquisitor** is a specialized reconnaissance tool written in Go, designed for mobile security researchers and penetration testers. It automates the discovery and security analysis of Deep Links and App Links within Android applications to identify critical vulnerabilities such as **Intent Redirection**, **Authentication Bypass**, and **Insecure WebView** implementations.

---
# 🎯 Overview

In modern Android applications, Deep Links often serve as gateways to sensitive functionalities. If these links are improperly secured—especially when associated with `exported` activities—they become high-value targets for attackers. This tool parses the `AndroidManifest.xml` to map out the entire deep link attack surface and generates ready-to-use Proof-of-Concept (POC) commands.

# Key Features
- **Automated Manifest Analysis:** Rapidly parses decompiled XML files to identify all `intent-filter` blocks.
- **Security Risk Scoring:** Automatically flags `android:exported="true"` activities that are accessible by external applications.
- **URI Construction:** Maps `scheme`, `host`, and `path` attributes into fully qualified URIs.
- **ADB Exploit Generator:** Produces instant `adb` shell commands for dynamic testing and verification.
- **Performance-Driven:** Built with Golang's efficient concurrency and regex engine for lightning-fast scanning.

# 🛠️ Technical Details
Security Checks Performed:
1. **Exported Activity Check:** Identifies if an activity can be launched by any app on the device.
2. **Scheme Enumeration:** Collects custom URI schemes (e.g., `myapp://`) which are often less protected than standard `https` links.
3. **Attack Surface Mapping:** Visualizes how an external URI maps to an internal Java/Kotlin class.

# Prerequisites
- Go 1.20 or higher.
- Apktool (for decompiling target APKs).

# Installation

```
git clone https://github.com/ikpehlivan/Andro-Deep-Link-Inquisitor.git
cd Andro-Deep-Link-Inquisitor
go mod init Andro-Deep-Link-Inquisitor
```

# Usage

```
Decompile your target APK:
apktool d target_app.apk

Run the Inquisitor:
go run main.go -manifest ./target_app/AndroidManifest.xml
```
# 📊 Sample Output
```
--- Target Activity: com.targetapp.InternalTransferActivity ---
[!] Security Status: EXPORTED (HIGH RISK)
   > Identified URI: target_app://transfer/confirm
     POC Exploit: adb shell am start -W -a android.intent.action.VIEW -d "target_app://transfer/confirm"
```
# ⚖️ Ethical Use & Disclaimer

This tool is created for educational and authorized security testing purposes only. Unauthorized access to or testing of mobile applications without prior consent is illegal. The developer assumes no liability for any misuse or damage caused by this program. Always stay ethical.

Developed by İlteriş Kaan Pehlivan

Web & Mobile Security Researcher | White Hat Hacker
