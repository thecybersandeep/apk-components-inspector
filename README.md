**APK Components Inspector**

*A simple-to-use Python tool that retrieves and lists exposed functionalities of Android applications (such as activities, services, receivers, and providers), derives actual intent extras attributes from Smali code, and scripts practical ADB commands for Android penetration testing.*

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/79c9430b-a0da-4149-9219-eb7b19ac24ae"
    alt="image"
    width="632"
  />
</p>

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

## License & Permissions

* **Unauthorized copying, reproduction, or redistribution of this tool is strictly forbidden.**

---

> **Happy Pentesting!**
