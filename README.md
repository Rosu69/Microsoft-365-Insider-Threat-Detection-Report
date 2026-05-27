# Microsoft 365 Insider Threat Detector
 
A PowerShell script that pulls user activity across Exchange, SharePoint, OneDrive, and Entra ID via the Microsoft Graph API, runs behavioral analysis across 10 detection checks, and produces a per-user risk score report flagging potential insider threats or compromised accounts.
 
This isn't a list of events. It's a behavioral profile. The script looks for patterns — someone downloading 400 files at 2am, a mail forwarding rule set up the week before someone resigned, an account dormant for 90 days suddenly accessing sensitive sites. That's what real UEBA tools do, and that's what this script does.
 
Completely read-only. Nothing in your tenant gets touched.
 
---
 
## What it detects
 
| # | Behavior | Why it matters |
|---|----------|----------------|
| 1 | External mail forwarding rules | Classic silent exfiltration technique |
| 2 | Bulk file downloads (100+ files) | Data theft before departure or after compromise |
| 3 | After-hours signin activity | Legitimate users follow patterns — anomalies stand out |
| 4 | Mass file deletion (50+ files) | Sabotage or covering tracks |
| 5 | Impossible travel | Two countries within 2 hours — physically impossible |
| 6 | Dormant account reactivation | Sleeping account suddenly active — credential stuffing signal |
| 7 | Failed logins then success | Brute force or password spray that worked |
| 8 | Privilege escalation | Role added to account — especially suspicious if self-assigned |
| 9 | Microsoft Identity Protection flag | Cross-referenced with MSFT's own threat intelligence |
| 10 | Admin role removed then bulk download | Timing correlation — someone knew they were losing access |
 
---
 
## Risk Scoring
 
Each detected behavior adds to the user's risk score. Scores are weighted by severity and context.
 
| Behavior | Base Score | Modifier |
|----------|-----------|----------|
| External mail forwarding | 80 | +20 if rule created in last 7 days |
| Bulk download 100+ files | 60 | +10 per additional 50 files |
| After-hours activity | 20 | +15 if also from new location |
| Mass deletion 50+ files | 70 | +20 if within 48hrs of role change |
| Impossible travel | 90 | None — always high |
| Dormant account active | 50 | +30 if privileged account |
| Failed then successful login | 60 | +20 if unfamiliar IP |
| Privilege escalation | 40 | +30 if self-assigned |
| MSFT Identity Protection flag | 20-80 | Based on Microsoft risk level |
| Admin removed + bulk download | 85 | Correlation bonus |
 
| Total Score | Risk Tier |
|-------------|-----------|
| 150+ | CRITICAL — Investigate immediately |
| 80-149 | HIGH — Review within 24 hours |
| 40-79 | MEDIUM — Monitor closely |
| Below 40 | LOW — Log and watch |
 
---
 
## Output
 
- `M365-InsiderThreat-Report.html` — per-user risk dashboard with behavioral findings, opens automatically in your browser
- `M365-InsiderThreat-Report.csv` — full export with scores and findings per user
---
 
## Requirements
 
- Windows PowerShell 5.1 or PowerShell 7+
- Microsoft Graph PowerShell SDK
- Entra ID account with **Security Reader** role minimum
- Microsoft 365 E3/E5 or equivalent licensing for audit log access
- Microsoft Entra ID P1/P2 for Identity Protection data (Check 9 — optional, others still run without it)
---
 
## Setup
 
### Step 1 — Install NuGet provider
 
```powershell
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
```
 
### Step 2 — Trust PowerShell Gallery
 
```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
```
 
### Step 3 — Install Microsoft Graph SDK
 
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```
 
### Step 4 — Import authentication module
 
```powershell
Import-Module Microsoft.Graph.Authentication
```
 
### Step 5 — Set execution policy
 
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
 
---
 
## Connecting to the Graph API
 
The script uses these read-only permission scopes:
 
| Scope | What it reads |
|-------|--------------|
| `AuditLog.Read.All` | Sign-in logs, file activity, directory audit events |
| `Directory.Read.All` | Users, roles, group memberships |
| `Reports.Read.All` | Usage and activity reports |
| `SecurityEvents.Read.All` | Identity Protection risky user data |
 
To connect:
 
```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "Reports.Read.All", "SecurityEvents.Read.All"
```
 
A browser window opens. Sign in with your work account and accept the permissions screen. All scopes are read-only.
 
> **Note:** `AuditLog.Read.All` is a higher-privilege read scope. Your account needs Security Reader or Global Reader in Entra ID. If you get an insufficient privileges error, check your role assignment under Identity > Roles and administrators in the Entra portal.
 
> **Admin consent:** If your organisation requires admin consent for Graph permissions, a Global Admin needs to grant it once. After that, any Security Reader can run the script without further approval.
 
---
 
## Running the script
 
```powershell
cd C:\Users\YourName\Documents
.\M365-InsiderThreat.ps1
```
 
The script will:
1. Connect to Microsoft Graph
2. Pull all users and sign-in activity
3. Pull SharePoint and OneDrive file events
4. Pull directory audit logs (role changes, forwarding rules)
5. Pull Microsoft Identity Protection risky users
6. Build a behavioral risk profile for every user
7. Run all 10 detection checks
8. Cross-correlate events across checks (e.g. role removal + download timing)
9. Assign risk scores and tiers
10. Output HTML and CSV reports
Runtime is 5-10 minutes depending on tenant size and audit log volume.
 
---
 
## Troubleshooting
 
**"Insufficient privileges" on AuditLog.Read.All**
Your account needs Security Reader or Global Reader in Entra ID. Check under Identity > Roles and administrators.
 
**Identity Protection data returns empty**
Requires Microsoft Entra ID P1 or P2 licensing. The other 9 checks will still run fine without it.
 
**Audit logs return very few events**
Your tenant may have a shorter retention window. Microsoft 365 E3 retains audit logs for 90 days. E5 retains for 365 days.
 
**Script runs but no users are flagged**
Either your tenant is clean (possible) or audit logging is not enabled. Check in the Microsoft Purview compliance portal under Audit > Search.
 
**"Cannot be loaded, not digitally signed"**
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
```
 
---
 
## Is this safe to run in production?
 
Yes. All Graph API scopes used are read-only. The script cannot modify, delete, disable, or create any user, rule, policy, or configuration. The only files it writes are the two report files saved locally on your machine.
 
Graph API read activity appears in your Entra sign-in logs under your account as a normal read operation.
 
---
 
## Badges
 
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue)
![Graph API](https://img.shields.io/badge/Microsoft%20Graph-v1.0-0078d4)
![UEBA](https://img.shields.io/badge/Behavioral-Analysis-red)
![Read Only](https://img.shields.io/badge/Tenant%20Impact-Read%20Only-brightgreen)
![Checks](https://img.shields.io/badge/Detection%20Checks-10-orange)
 
---
 
## Author

Roshan Tamang
www.linkedin.com/in/roshan-tamangg
