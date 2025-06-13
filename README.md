**APK Components Inspector**

*A simple-to-use Python tool that retrieves and lists exposed functionalities of Android applications (such as activities, services, receivers, and providers), derives actual intent extras attributes from Smali code, and scripts practical ADB commands for Android penetration testing.*

<img width="777" alt="image" src="https://github.com/user-attachments/assets/fdd5ac8b-1e66-4245-a8dd-c06a0e63f824" />

## How It Works

<img width="1115" alt="image" src="https://github.com/user-attachments/assets/2751b906-2b46-4e5c-b5e1-ad1f0428e8e4" />


[![License: CC BY-NC-ND 4.0](https://licensebuttons.net/l/by-nc-nd/4.0/88x31.png)](https://creativecommons.org/licenses/by-nc-nd/4.0/)



---

## Overview

APK Components Inspector is a Command Line utility for security researchers which automatically generates ADB commands to access exported Android components hiding in the APK files. By deriving real intent extras (name, type) from Smali code—rather than guessing—you save time and eliminate manual guesswork.

It unpacks the APK, enumerates exported activities, services, receivers, and providers, and then analyzes each component’s Smali to extract actual parameter names (e.g., what `getStringExtra("username")` really expects). Finally, it outputs ready-to-run `adb shell` commands.

> **⚠️ Notice:** This tool is intended for research and educational purposes only. Please do not copy, or redistribute it without the author's permission

---

## Requirements

1. **Python3.X+**
2. **apktool 2.6.0+**
3. **Androguard 3.3.5** (pip install androguard==3.3.5)
4. Unix-like OS (Linux/macOS/WSL) with tools installed and in your `PATH`.


## 🚀 Installation
```bash
git clone https://github.com/thecybersandeep/apk-components-inspector
cd apk-components-inspector
python3 -m venv venv
source venv/bin/activate
pip install androguard==3.3.5 rich
```

---

# Run your tool

```
python apk-components-inspector.py some.apk
```

---

<img width="1624" alt="image" src="https://github.com/user-attachments/assets/16d832c4-5350-4427-a3d9-4a2ff8756b74" />


> **Note:** This tool does not guarantee a working exploit for every component. It automates about **74%** of the work, but a pentester must still validate, tweak, and test the generated commands to achieve an actual exploit.

---

## Comparison with Modern Tools


| **Use Case** | **APK Components Inspector** | **Drozer** | **Manual ADB Commands** | **MobSF** |
|--------------|-----------------------------|------------|------------------------|-----------|
| **Rapid Testing of Exported Components** | ✅ Instantly generates precise ADB commands for exported components (activities, services, receivers, providers), enabling testing in seconds. | ❌ Requires manual module execution and console setup, slowing down testing. | ❌ Demands manual crafting of commands, highly time-consuming. | ❌ Identifies components but requires manual command creation, delaying testing. |
| **Targeting Specific Intent Extras** | ✅ Extracts real intent extras (names and types) from Smali code for accurate exploitation. | ❌ Limited to runtime extra extraction, less precise and partially automated. | ❌ No extra extraction, relies on guesswork or manual reverse-engineering. | ❌ Lacks intent extra extraction, missing critical exploitation details. |
| **Accessibility for All Skill Levels** | ✅ Simple command-line interface—just input the APK for quick results, no complex setup. | ❌ Steep learning curve with agent installation and console expertise needed. | ❌ Requires deep ADB and Android knowledge, inaccessible to beginners. | ❌ Web interface is user-friendly, but exploitation requires manual expertise. |
| **Focused Exploitation Tasks** | ✅ Targets exported components with laser focus, delivering fast, relevant data. | ❌ Broad dynamic testing dilutes focus on component-specific exploits. | ❌ Unfocused, no guidance for targeting components. | ❌ Broad analysis overwhelms with unrelated data, less focus on components. |
| **Time-Critical Analysis** | ✅ Automates the process, minimizing manual effort and speeding up analysis. | ❌ Manual interaction and setup make it slower for urgent tasks. | ❌ Slowest due to fully manual command research and creation. | ❌ Slow for exploitation due to manual steps post-analysis. |


---

## How It Works

1. **Decompile APK**
   Internally runs:

   ```bash
   apktool d <apk_path> -o <output_dir> -f
   ```

   → Unpacks resources and Smali into `<output_dir>/`.

2. **Parse Manifest**
   Uses Python’s `xml.etree.ElementTree` to read `AndroidManifest.xml` and list components marked with `android:exported="true"` (or implicitly exported in older API levels).

3. **Locate Smali Files**
   For each exported component’s fully qualified class name (e.g., `com.example.app.LoginActivity` → `smali/.../LoginActivity.smali`), the script loads the corresponding Smali file(s).

4. **Extract Real Extras**
   Inside each Smali file, it scans relevant methods (`onCreate`, `onHandleIntent`, `onReceive`) for patterns such as:

   ```smali
   invoke-virtual {p0, v0, "username", v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
   ```

   Whenever it sees `get<Type>Extra("some_key")`, it captures `some_key` and infers `<Type>` to decide between `--es`, `--ei`, etc., assigning a placeholder (e.g., `"test"` for strings, `0` for ints, `true` for booleans).

5. **Build ADB Commands**

   * **Activities/Services/Broadcasts:**

     * `adb shell am start|service|broadcast`
     * `-n <package>/<ComponentClass>`
     * If `<intent-filter>` actions or data URIs exist, append `-a <action>` and `-d <URI>`.
     * For detected extras: append `-e` / `--es` / `--ei` / `--ez` with placeholder values.
   * **Content Providers:**

     * Reads provider authorities and path segments from `AndroidManifest.xml`.
     * If Smali CRUD calls reveal table/column names (e.g., `query("notes", new String[]{"_id","title","content"},…)`), it generates:

       ```bash
       adb shell content query --uri content://<authority>/<path>
       adb shell content insert --uri content://<authority>/<path> --bind title:s:"Sample" --bind content:s:"Data"
       ```


---

## License & Permissions

* **Unauthorized copying, reproduction, or redistribution of this tool is strictly forbidden.**

---

> **Happy Pentesting!**
