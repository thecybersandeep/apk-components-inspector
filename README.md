**APK Components Inspector**

*A simple-to-use Python tool that retrieves and lists exposed functionalities of Android applications (such as activities, services, receivers, and providers), derives actual intent extras attributes from Smali code, and scripts practical ADB commands for Android penetration testing.*

<img width="777" alt="image" src="https://github.com/user-attachments/assets/fdd5ac8b-1e66-4245-a8dd-c06a0e63f824" />

> **Note:** This tool does not guarantee a working exploit for every component. It automates about **70%** of the work, but a pentester must still validate, tweak, and test the generated commands to achieve an actual exploit.

---

## Overview

APK Components Inspector is a Command Line utility for security researchers which automatically generates ADB commands to access exported Android components hiding in the APK files. By deriving real intent extras (name, type) from Smali code—rather than guessing—you save time and eliminate manual guesswork.

It unpacks the APK, enumerates exported activities, services, receivers, and providers, and then analyzes each component’s Smali to extract actual parameter names (e.g., what `getStringExtra("username")` really expects). Finally, it outputs ready-to-run `adb shell` commands.

> **⚠️ Notice:** This tool is intended for research and educational purposes only. Please do not copy, or redistribute it without the author's permission

---

## Features

### Automated APK Decompilation

* Unpacks and decodes resources via **apktool**.
* Locates `AndroidManifest.xml` and all relevant Smali files in one step.

### Smali-Level Extraction of Real Intent Extras

* Detects calls like `getStringExtra()`, `getIntExtra()`, `getParcelableExtra()` inside `onCreate`, `onReceive`, etc.
* Infers data types and placeholder values (e.g., `--es username "test"`, `--ei count 0`).

### Exported Component Enumeration

* Filters only **exported** components (no rooting needed).
* Lists activities, services, broadcast receivers, and content providers reachable from external processes.

### Automatic ADB Command Generation

* **Activities & Services:** Builds `adb shell am start` / `startservice` with `-n`, `-a`, and `-d` flags.
* **Broadcast Receivers:** Constructs `adb shell am broadcast` lines.
* **Content Providers:** Generates `adb shell content query`, `insert`, `update`, or `delete` commands based on discovered URIs and column names.

### Lightweight, No Agent Suggested

* No on-device agent (unlike Drozer).
* No full web server required (unlike MobSF).
* Only needs **Python 3**, **apktool**, and the [`androguard`](https://github.com/androguard/androguard) library.

### Customizable & Open Source

* Entire logic resides in a single script: `apk-components-inspector.py`.
* Modify Smali parsing rules, URI constructors, or extraction routines to suit bespoke frameworks or proprietary code.

---

## Requirements

1. **Python3.X+**
2. **apktool 2.6.0+**
3. **Androguard 3.3.5.x+** (pip install androguard==3.3.5)
4. Unix-like OS (Linux/macOS/WSL) with **ADB** installed and in your `PATH`.

---

## Setup

1. **Clone or download** this repository—or simply place `apk-components-inspector.py` into your working directory.
2. **(Optional)** Create a virtual environment and install dependencies:

   ```bash
pip3 uninstall androguard -y (fixed)
pip3 install androguard==3.3.5 rich

   ```
3. **Verify** that `apktool` and `adb` are available:

   ```bash
   apktool --version
   ```

---

## Usage

### Basic Command

```bash
python3 apk-components-inspector.py <path/to/app.apk>
```

This sequence will:

1. Decompile `app.apk` to `<app_name>_decompiled/`.
2. Parse `AndroidManifest.xml` to identify exported components.
3. Traverse each component’s Smali code to extract real intent extras.
4. Print a summary table of components alongside ready-to-run ADB commands.

<img width="1624" alt="image" src="https://github.com/user-attachments/assets/16d832c4-5350-4427-a3d9-4a2ff8756b74" />


### Options

```text
Usage: apk-components-inspector.py [options] <apk_path>

Options:
  -h, --help           Show help and exit.
  -v, --verbose        Enable verbose logging (prints each Smali file as it’s processed).
  -q, --quiet          Minimal output (only show final summary and commands).
  --keep-workdir       Preserve the decompiled folder instead of deleting it.
  --output <file>      Write results (component list + ADB commands) to a text file.
```

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
