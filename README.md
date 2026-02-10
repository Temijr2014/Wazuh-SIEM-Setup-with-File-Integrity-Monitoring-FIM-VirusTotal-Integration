# Wazuh SIEM Setup with File Integrity Monitoring (FIM) & VirusTotal Integration

This documentation explains how to set up **Wazuh SIEM**, enable **File Integrity Monitoring (FIM)**, and integrate **VirusTotal API** to detect and alert on potential malware activity. This project is designed for **SOC junior-level practice** and home lab environments.

---

## 📌 Project Overview

In this project, we:

* Install and configure **Wazuh (Manager, Indexer, Dashboard)**
* Deploy a **Wazuh Agent**
* Enable **File Integrity Monitoring (FIM)**
* Integrate **VirusTotal API** for malware hash analysis
* Generate alerts for suspicious file changes and malware

---

## 🧰 Requirements

* Ubuntu Server 20.04/22.04 (Wazuh Server)
* Ubuntu or Windows endpoint (Agent)
* Minimum 4 GB RAM (8 GB recommended)
* Internet access
* VirusTotal API key (free tier)

---

## 🛠️ Step 1: Install Wazuh All-in-One Server

```bash
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

After installation, note the **Dashboard URL** and login credentials.

Access Dashboard:

```
https://<server-ip>
```

---

## 🧩 Step 2: Add a Wazuh Agent

### Ubuntu Agent

```bash
curl -sO https://packages.wazuh.com/4.x/apt/wazuh-agent_4.x.x-1_amd64.deb
sudo dpkg -i wazuh-agent_4.x.x-1_amd64.deb
```

Configure agent:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Set manager IP:

```xml
<client>
  <server>
    <address>MANAGER_IP</address>
  </server>
</client>
```

Start agent:

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## 📁 Step 3: Enable File Integrity Monitoring (FIM)

 Add or edit FIM section:
<img width="1920" height="991" alt="Ubuntu (Snapshot 1)  Running  - Oracle VirtualBox 09_02_2026 07_01_28" src="https://github.com/user-attachments/assets/03c693ce-6b01-416e-879b-6424a7123efb" />

Restart agent:

```bash
sudo systemctl restart wazuh-agent
```

---

## 🧪 Step 4: Test FIM Alerts

Create a test file:

```bash
touch /tmp/malware
```

## View alerts in Dashboard:
<img width="1920" height="991" alt="Ubuntu (Snapshot 1)  Running  - Oracle VirtualBox 09_02_2026 07_10_06" src="https://github.com/user-attachments/assets/11bca500-76c5-43d1-b035-9a7b0a7c8f33" />

---

## 🦠 Step 5: Integrate VirusTotal API

### Get API Key

* Create a free account on VirusTotal
* Copy your API key

---

### Configure VirusTotal Integration

Edit manager configuration:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add:

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_API_KEY</api_key>
  <rule_id>100200</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh Manager:

```bash
sudo systemctl restart wazuh-manager
```

---

## 🚨 Step 6: Malware Detection Workflow

1. File is created or modified
2. FIM detects change
3. Hash is generated
4. Hash sent to VirusTotal
5. Alert generated if malicious

---

## 🧪 Step 7: Malware Test (Safe)

Download EICAR test file:

```bash
curl -o eicar.com.txt https://secure.eicar.org/eicar.com.txt
```
---
## 📊 Step 8: Viewing Alerts
<img width="1920" height="991" alt="Ubuntu (Snapshot 1)  Running  - Oracle VirtualBox 09_02_2026 07_36_37" src="https://github.com/user-attachments/assets/6a4627ea-efba-4a2f-be79-87c697cd04d2" />
<img width="1920" height="991" alt="Ubuntu (Snapshot 1)  Running  - Oracle VirtualBox 09_02_2026 07_37_08" src="https://github.com/user-attachments/assets/170ffdfe-9468-4262-8090-6ddd9019f9a5" />

---

## 🔒 Security Best Practices

* Monitor only critical directories
* Rotate VirusTotal API keys
* Avoid scanning large directories
* Use least privilege

---

## 🎯 SOC Use Case

* Detect unauthorized file changes
* Identify malware via hash reputation
* Correlate endpoint activity
* Practice SIEM alert analysis

---

## ✅ Conclusion

This project demonstrates practical SOC skills using **Wazuh SIEM**, **File Integrity Monitoring**, and **VirusTotal integration** to detect and respond to malware threats.

---

**Author:** Temiloluwa Owolana
**Focus:** Cybersecurity | SOC Analyst (Junior)

