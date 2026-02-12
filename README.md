# Azure Honeypot SOC Lab

A hands-on cybersecurity project deploying a Windows honeypot in Microsoft Azure, integrating with Sentinel SIEM for threat monitoring and attack visualization.

![Lab Architecture](images/Pasted%20image%2020260212114444.png)

## Overview

This project demonstrates the deployment of a **Windows 10 honeypot** in Microsoft Azure, designed to attract and monitor malicious activity. The lab integrates with **Microsoft Sentinel** (cloud-native SIEM) to collect, analyze, and visualize security events from attackers worldwide.

**Objectives:**
- Deploy a vulnerable Windows VM exposed to the internet
- Configure centralized logging with Azure Log Analytics
- Analyze authentication attempts using KQL (Kusto Query Language)
- Visualize geographic distribution of attacks

## Architecture

```
Internet
    |
    v
Network Security Group (NSG) - Open RDP (3389)
    |
    v
Windows 10 VM (Honeypot) - Firewall Disabled
    |
    v
Azure Monitor Agent (AMA)
    |
    v
Log Analytics Workspace
    |
    v
Microsoft Sentinel (KQL + Watchlists + Workbooks)
```

## Deployment Steps

### 1. Resource Group

Create a resource group to organize lab resources:

```bash
az group create --name rg-honeypot-lab --location eastus
```

![Resource Group](images/Pasted%20image%2020260124180652.png)

### 2. Virtual Network

Deploy a virtual network:

```bash
az network vnet create \
  --resource-group rg-honeypot-lab \
  --name vnet-honeypot \
  --address-prefix 10.0.0.0/16 \
  --subnet-name subnet-honeypot \
  --subnet-prefix 10.0.1.0/24
```

![Virtual Network](images/Pasted%20image%2020260124181210.png)

### 3. Virtual Machine

Deploy Windows 10 VM as honeypot:

![VM Configuration](images/Pasted%20image%2020260124184141.png)

![All Resources](images/Pasted%20image%2020260124184652.png)

### 4. Network Security Configuration

**Remove protective inbound rules** to expose the honeypot:

Before:
![RDP Rule](images/Pasted%20image%2020260124185124.png)

After (exposed):
![Open Ports](images/Pasted%20image%2020260124185330.png)

**Disable Windows Firewall** via RDP:

```powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

![Windows VM](images/Pasted%20image%2020260124185935.png)

![Firewall Disabled](images/Pasted%20image%2020260124190858.png)

Connectivity test:
![Ping Test](images/Pasted%20image%2020260124191027.png)

### 5. Log Analytics Workspace

Create workspace for log storage:

```bash
az monitor log-analytics workspace create \
  --resource-group rg-honeypot-lab \
  --name law-honeypot \
  --location eastus
```

![Log Analytics](images/Pasted%20image%2020260124192926.png)

### 6. Microsoft Sentinel Integration

**Enable Sentinel** and link the workspace.

**Install Azure Monitor Agent** on the VM:

![Azure Monitor Agent](images/Pasted%20image%2020260124194711.png)

**Configure Data Collection Rule** for Windows Security Events:

![Data Collection 1](images/Pasted%20image%2020260124195359.png)

![Data Collection 2](images/Pasted%20image%2020260124195432.png)

## Data Verification

After running overnight, verify ingestion:

![Logs Workspace](images/Pasted%20image%2020260125155047.png)

Basic query:
```kusto
SecurityEvent
| take 100
```

## Threat Analysis

### Failed Login Attempts

Query Event ID 4625 (Failed Logon) from a specific attacker IP:

```kusto
SecurityEvent
| where IpAddress == "112.169.121.194"
| where EventID == 4625
| order by TimeGenerated desc
```

![Failed Logons](images/Pasted%20image%2020260125160325.png)

### IP Geolocation

The IP `112.169.121.194` traced to **Chile**:

![IP Geolocation](images/Pasted%20image%2020260125160539.png)

## Attack Visualization

### GeoIP Enrichment

Upload GeoIP CSV to Sentinel Watchlists:

![Watchlist](images/Pasted%20image%2020260125162801.png)

### Enriched Query

```kusto
let GeoIP_Full = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent 
| where IpAddress == "112.169.121.194"
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIP_Full, IpAddress, network);
WindowsEvents
```

![Enriched Results](images/Pasted%20image%2020260125172003.png)

### Interactive Attack Map

Create a Workbook in Sentinel with this JSON configuration:

```json
{
    "type": 3,
    "content": {
        "version": "KqlItem/1.0",
        "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
        "visualization": "map",
        "mapSettings": {
            "locInfo": "LatLong",
            "latitude": "latitude",
            "longitude": "longitude",
            "sizeSettings": "FailureCount",
            "itemColorSettings": {
                "type": "heatmap",
                "heatmapPalette": "greenRed"
            }
        }
    }
}
```

Initial results (first day):

![Attack Map Day 1](images/Pasted%20image%2020260125173209.png)

Map metrics configuration:

![Map Metrics](images/Pasted%20image%2020260125173748.png)

## Results

### After 1 Month

The honeypot recorded **thousands of failed login attempts** from attackers worldwide:

![Attack Map 1 Month](images/Pasted%20image%2020260212113515.png)

**Key Findings:**
- Constant 24/7 automated attacks
- Multiple countries identified
- Common usernames: `admin`, `user`, `minsal`
- Immediate targeting upon exposure

## Skills Developed

- Microsoft Azure & Sentinel
- KQL (Kusto Query Language)
- Windows Security Event Analysis
- Threat Intelligence & GeoIP Enrichment
- Security Data Visualization

## Conclusion

This lab demonstrates a complete SOC workflow: infrastructure deployment, log ingestion, threat analysis, and visualization. The results confirm that any exposed internet service faces immediate automated attacks, emphasizing the need for robust security monitoring.

---

**Technologies:** Azure | Sentinel | KQL | Windows Security | GeoIP
