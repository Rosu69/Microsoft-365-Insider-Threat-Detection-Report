# ============================================================
#  Microsoft 365 Insider Threat Detector
#  Read-only | Safe for production | No changes made
#  Permissions: AuditLog.Read.All, Directory.Read.All,
#               Reports.Read.All, SecurityEvents.Read.All
# ============================================================

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

# ===========================
#  CONNECT
# ===========================
Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All", "Reports.Read.All", "SecurityEvents.Read.All"

# ===========================
#  CONFIGURATION
# ===========================
$lookbackDays        = 30
$afterHoursStart     = 20  # 8pm
$afterHoursEnd       = 6   # 6am
$bulkDownloadThresh  = 100
$bulkDeleteThresh    = 50
$dormantDays         = 60
$travelWindowHours   = 2

$startDate = (Get-Date).AddDays(-$lookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endDate   = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")

Write-Host "[*] Analysis window: Last $lookbackDays days ($startDate to $endDate)" -ForegroundColor Gray

# ===========================
#  PULL USER DATA
# ===========================
Write-Host "[*] Pulling all users..." -ForegroundColor Cyan
$allUsers = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,UserType,SignInActivity,CreatedDateTime"
$userLookup = @{}
foreach ($u in $allUsers) { $userLookup[$u.Id] = $u }
Write-Host "    Found $($allUsers.Count) users." -ForegroundColor Gray

# ===========================
#  PULL AUDIT LOGS
# ===========================
Write-Host "[*] Pulling audit logs (this may take a moment)..." -ForegroundColor Cyan

# SharePoint and OneDrive file activity
$fileActivityUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $startDate and activityDateTime le $endDate and loggedByService eq 'SharePoint'&`$top=500"

$fileEvents = @()
$nextLink   = $fileActivityUri
while ($nextLink) {
    $response  = Invoke-MgGraphRequest -Uri $nextLink -Method GET
    $fileEvents += $response.value
    $nextLink  = $response.'@odata.nextLink'
    if ($fileEvents.Count % 500 -eq 0) {
        Write-Host "    Pulled $($fileEvents.Count) file events so far..." -ForegroundColor Gray
    }
}
Write-Host "    Total file events: $($fileEvents.Count)" -ForegroundColor Gray

# Sign-in logs
Write-Host "[*] Pulling sign-in logs..." -ForegroundColor Cyan
$signInUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=createdDateTime ge $startDate and createdDateTime le $endDate&`$top=500"

$signInEvents = @()
$nextLink     = $signInUri
$pageCount    = 0
while ($nextLink -and $pageCount -lt 10) {
    $response      = Invoke-MgGraphRequest -Uri $nextLink -Method GET
    $signInEvents += $response.value
    $nextLink      = $response.'@odata.nextLink'
    $pageCount++
}
Write-Host "    Total sign-in events: $($signInEvents.Count)" -ForegroundColor Gray

# Directory audit logs (role changes, forwarding rules)
Write-Host "[*] Pulling directory audit logs..." -ForegroundColor Cyan
$dirAuditUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $startDate and activityDateTime le $endDate&`$top=500"

$dirEvents = @()
$nextLink   = $dirAuditUri
$pageCount  = 0
while ($nextLink -and $pageCount -lt 10) {
    $response   = Invoke-MgGraphRequest -Uri $nextLink -Method GET
    $dirEvents += $response.value
    $nextLink   = $response.'@odata.nextLink'
    $pageCount++
}
Write-Host "    Total directory events: $($dirEvents.Count)" -ForegroundColor Gray

# Risky users from Identity Protection
Write-Host "[*] Pulling risky users from Identity Protection..." -ForegroundColor Cyan
$riskyUsers = @()
try {
    $riskyUsersData = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers" -Method GET
    $riskyUsers     = $riskyUsersData.value
    Write-Host "    Found $($riskyUsers.Count) risky users flagged by Microsoft." -ForegroundColor Gray
} catch {
    Write-Host "    [!] Could not pull risky users - may require additional licensing." -ForegroundColor Yellow
}

# ===========================
#  BUILD USER RISK PROFILES
# ===========================
Write-Host "[*] Building behavioral risk profiles per user..." -ForegroundColor Cyan

$userRiskProfiles = @{}

foreach ($user in $allUsers) {
    $userRiskProfiles[$user.Id] = [PSCustomObject]@{
        UserId          = $user.Id
        DisplayName     = $user.DisplayName
        UPN             = $user.UserPrincipalName
        RiskScore       = 0
        RiskTier        = "LOW"
        Findings        = @()
        DownloadCount   = 0
        DeleteCount     = 0
        AfterHoursCount = 0
        SignInCount     = 0
        FlaggedByMSFT   = $false
    }
}

# ===========================
#  CHECK 1 — EXTERNAL MAIL FORWARDING RULES
# ===========================
Write-Host "[*] Check 1: External mail forwarding rules..." -ForegroundColor Gray
$forwardingEvents = $dirEvents | Where-Object {
    $_.activityDisplayName -match "forward" -or
    $_.activityDisplayName -match "InboxRule" -or
    $_.activityDisplayName -match "Set-Mailbox"
}

foreach ($event in $forwardingEvents) {
    $userId = $event.initiatedBy.user.id
    if (-not $userId -or -not $userRiskProfiles.ContainsKey($userId)) { continue }

    $profile = $userRiskProfiles[$userId]
    $score   = 80

    $eventDate   = [DateTime]$event.activityDateTime
    $ageInDays   = ((Get-Date) - $eventDate).TotalDays
    if ($ageInDays -le 7) { $score += 20 }

    $profile.RiskScore += $score
    $profile.Findings  += "External mail forwarding rule detected (Score: +$score)"
}

# ===========================
#  CHECK 2 — BULK FILE DOWNLOADS
# ===========================
Write-Host "[*] Check 2: Bulk file downloads..." -ForegroundColor Gray
$downloadEvents = $fileEvents | Where-Object {
    $_.activityDisplayName -match "FileDownloaded" -or
    $_.activityDisplayName -match "FileSyncDownloadedFull"
}

$downloadsByUser = $downloadEvents | Group-Object { $_.initiatedBy.user.id }
foreach ($group in $downloadsByUser) {
    $userId = $group.Name
    if (-not $userId -or -not $userRiskProfiles.ContainsKey($userId)) { continue }

    $count   = $group.Count
    $profile = $userRiskProfiles[$userId]
    $profile.DownloadCount = $count

    if ($count -ge $bulkDownloadThresh) {
        $extraBundles = [math]::Floor(($count - $bulkDownloadThresh) / 50)
        $score        = 60 + ($extraBundles * 10)
        $profile.RiskScore += $score
        $profile.Findings  += "Bulk download: $count files in last $lookbackDays days (Score: +$score)"
    }
}

# ===========================
#  CHECK 3 — AFTER-HOURS ACTIVITY
# ===========================
Write-Host "[*] Check 3: After-hours signin activity..." -ForegroundColor Gray
$afterHoursSignIns = $signInEvents | Where-Object {
    $hour = ([DateTime]$_.createdDateTime).Hour
    $hour -ge $afterHoursStart -or $hour -lt $afterHoursEnd
}

$afterHoursByUser = $afterHoursSignIns | Group-Object userId
foreach ($group in $afterHoursByUser) {
    $userId = $group.Name
    if (-not $userId -or -not $userRiskProfiles.ContainsKey($userId)) { continue }

    $count   = $group.Count
    $profile = $userRiskProfiles[$userId]
    $profile.AfterHoursCount = $count

    if ($count -ge 5) {
        $score = 20
        $profile.RiskScore += $score
        $profile.Findings  += "After-hours activity: $count sign-ins outside business hours (Score: +$score)"
    }
}

# ===========================
#  CHECK 4 — MASS FILE DELETION
# ===========================
Write-Host "[*] Check 4: Mass file deletion..." -ForegroundColor Gray
$deleteEvents = $fileEvents | Where-Object {
    $_.activityDisplayName -match "FileDeleted" -or
    $_.activityDisplayName -match "FolderDeleted"
}

$deletesByUser = $deleteEvents | Group-Object { $_.initiatedBy.user.id }
foreach ($group in $deletesByUser) {
    $userId = $group.Name
    if (-not $userId -or -not $userRiskProfiles.ContainsKey($userId)) { continue }

    $count   = $group.Count
    $profile = $userRiskProfiles[$userId]
    $profile.DeleteCount = $count

    if ($count -ge $bulkDeleteThresh) {
        $score = 70
        $profile.RiskScore += $score
        $profile.Findings  += "Mass deletion: $count files deleted in last $lookbackDays days (Score: +$score)"
    }
}

# ===========================
#  CHECK 5 — IMPOSSIBLE TRAVEL
# ===========================
Write-Host "[*] Check 5: Impossible travel..." -ForegroundColor Gray
$signInsByUser = $signInEvents | Group-Object userId
foreach ($group in $signInsByUser) {
    $userId  = $group.Name
    if (-not $userId -or -not $userRiskProfiles.ContainsKey($userId)) { continue }

    $events  = $group.Group | Sort-Object createdDateTime
    $profile = $userRiskProfiles[$userId]

    for ($i = 0; $i -lt $events.Count - 1; $i++) {
        $e1 = $events[$i]
        $e2 = $events[$i + 1]

        $loc1 = $e1.location.countryOrRegion
        $loc2 = $e2.location.countryOrRegion

        if ($loc1 -and $loc2 -and $loc1 -ne $loc2) {
            $t1      = [DateTime]$e1.createdDateTime
            $t2      = [DateTime]$e2.createdDateTime
            $hourGap = ([math]::Abs(($t2 - $t1).TotalHours))

            if ($hourGap -le $travelWindowHours) {
                $score = 90
                $profile.RiskScore += $score
                $profile.Findings  += "Impossible travel: $loc1 to $loc2 in $([math]::Round($hourGap,1)) hours (Score: +$score)"
                break
            }
        }
    }
}

# ===========================
#  CHECK 6 — DORMANT ACCOUNT REACTIVATION
# ===========================
Write-Host "[*] Check 6: Dormant account reactivation..." -ForegroundColor Gray
foreach ($user in $allUsers) {
    $profile = $userRiskProfiles[$user.Id]
    if (-not $profile) { continue }

    $lastSignIn = $null
    if ($user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
        $lastSignIn = [DateTime]$user.SignInActivity.LastSignInDateTime
    }

    if ($lastSignIn) {
        $daysSinceLastSignIn = ((Get-Date) - $lastSignIn).TotalDays

        # Check if they had recent activity in our window despite long absence before
        $recentActivity = $signInEvents | Where-Object { $_.userId -eq $user.Id }
        if ($recentActivity.Count -gt 0 -and $daysSinceLastSignIn -lt $lookbackDays) {
            # Account was dormant but is now active
            $dormantCheck = (Get-Date).AddDays(-($lookbackDays + $dormantDays))
            if ($lastSignIn -gt (Get-Date).AddDays(-$lookbackDays) -and
                $lastSignIn -lt (Get-Date).AddDays(-($lookbackDays - 5))) {
                $score = 50
                $profile.RiskScore += $score
                $profile.Findings  += "Dormant account reactivated after $([math]::Round($daysSinceLastSignIn)) days inactive (Score: +$score)"
            }
        }
    }
}

# ===========================
#  CHECK 7 — FAILED LOGINS THEN SUCCESS
# ===========================
Write-Host "[*] Check 7: Failed logins followed by success..." -ForegroundColor Gray
$failedSignIns   = $signInEvents | Where-Object { $_.status.errorCode -ne 0 }
$successSignIns  = $signInEvents | Where-Object { $_.status.errorCode -eq 0 }

$failsByUser = $failedSignIns | Group-Object userId
foreach ($group in $failsByUser) {
    $userId = $group.Name
    if (-not $userId -or -not $userRiskProfiles.ContainsKey($userId)) { continue }

    $failCount = $group.Count
    if ($failCount -lt 5) { continue }

    # Check if they eventually succeeded
    $userSuccesses = $successSignIns | Where-Object { $_.userId -eq $userId }
    if ($userSuccesses.Count -gt 0) {
        $profile = $userRiskProfiles[$userId]
        $score   = 60
        $profile.RiskScore += $score
        $profile.Findings  += "$failCount failed sign-ins followed by successful access (Score: +$score)"
    }
}

# ===========================
#  CHECK 8 — PRIVILEGE ESCALATION
# ===========================
Write-Host "[*] Check 8: Privilege escalation events..." -ForegroundColor Gray
$roleAddEvents = $dirEvents | Where-Object {
    $_.activityDisplayName -match "Add member to role" -or
    $_.activityDisplayName -match "Add eligible member to role"
}

foreach ($event in $roleAddEvents) {
    $targetId = $null
    if ($event.targetResources) {
        $targetId = $event.targetResources[0].id
    }
    if (-not $targetId -or -not $userRiskProfiles.ContainsKey($targetId)) { continue }

    $profile = $userRiskProfiles[$targetId]
    $score   = 40

    # Self-assigned escalation
    $initiatorId = $event.initiatedBy.user.id
    if ($initiatorId -eq $targetId) { $score += 30 }

    $profile.RiskScore += $score
    $profile.Findings  += "Privilege escalation detected (Score: +$score)"
}

# ===========================
#  CHECK 9 — FLAGGED BY MICROSOFT IDENTITY PROTECTION
# ===========================
Write-Host "[*] Check 9: Cross-referencing Microsoft Identity Protection flags..." -ForegroundColor Gray
foreach ($riskyUser in $riskyUsers) {
    $userId = $riskyUser.id
    if (-not $userId -or -not $userRiskProfiles.ContainsKey($userId)) { continue }

    $profile = $userRiskProfiles[$userId]
    $msRisk  = $riskyUser.riskLevel
    $msState = $riskyUser.riskState

    $score = switch ($msRisk) {
        "high"   { 80 }
        "medium" { 40 }
        "low"    { 20 }
        default  { 10 }
    }

    $profile.RiskScore   += $score
    $profile.FlaggedByMSFT = $true
    $profile.Findings    += "Flagged by Microsoft Identity Protection - Risk: $msRisk, State: $msState (Score: +$score)"
}

# ===========================
#  CHECK 10 — ADMIN ROLE REMOVED THEN BULK DOWNLOAD
# ===========================
Write-Host "[*] Check 10: Admin role removed then bulk download correlation..." -ForegroundColor Gray
$roleRemoveEvents = $dirEvents | Where-Object {
    $_.activityDisplayName -match "Remove member from role"
}

foreach ($event in $roleRemoveEvents) {
    $targetId = $null
    if ($event.targetResources) {
        $targetId = $event.targetResources[0].id
    }
    if (-not $targetId -or -not $userRiskProfiles.ContainsKey($targetId)) { continue }

    $profile     = $userRiskProfiles[$targetId]
    $roleDate    = [DateTime]$event.activityDateTime
    $windowEnd   = $roleDate.AddHours(48)

    # Check if they downloaded a lot within 48hrs of role removal
    $correlatedDownloads = $downloadEvents | Where-Object {
        $_.initiatedBy.user.id -eq $targetId -and
        ([DateTime]$_.activityDateTime) -ge $roleDate -and
        ([DateTime]$_.activityDateTime) -le $windowEnd
    }

    if ($correlatedDownloads.Count -ge 20) {
        $score = 85
        $profile.RiskScore += $score
        $profile.Findings  += "Admin role removed then $($correlatedDownloads.Count) downloads within 48hrs (Score: +$score)"
    }
}

# ===========================
#  FINALIZE RISK TIERS
# ===========================
foreach ($profile in $userRiskProfiles.Values) {
    $profile.RiskTier = switch ($profile.RiskScore) {
        { $_ -ge 150 } { "CRITICAL" }
        { $_ -ge 80  } { "HIGH"     }
        { $_ -ge 40  } { "MEDIUM"   }
        default         { "LOW"      }
    }
}

# ===========================
#  FILTER TO FLAGGED USERS ONLY
# ===========================
$flaggedUsers = $userRiskProfiles.Values |
    Where-Object { $_.RiskScore -gt 0 } |
    Sort-Object RiskScore -Descending

$critCount = ($flaggedUsers | Where-Object { $_.RiskTier -eq "CRITICAL" }).Count
$highCount = ($flaggedUsers | Where-Object { $_.RiskTier -eq "HIGH"     }).Count
$medCount  = ($flaggedUsers | Where-Object { $_.RiskTier -eq "MEDIUM"   }).Count
$lowCount  = ($flaggedUsers | Where-Object { $_.RiskTier -eq "LOW"      }).Count

# ===========================
#  TERMINAL PREVIEW
# ===========================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  M365 INSIDER THREAT DETECTION REPORT" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Users analyzed    : $($allUsers.Count)"
Write-Host "  Users flagged     : $($flaggedUsers.Count)"
Write-Host "  CRITICAL          : $critCount"
Write-Host "  HIGH              : $highCount"
Write-Host "  MEDIUM            : $medCount"
Write-Host "  LOW               : $lowCount"
Write-Host ""
$flaggedUsers | Select-Object -First 10 | Format-Table DisplayName, UPN, RiskScore, RiskTier -AutoSize

# ===========================
#  CSV EXPORT
# ===========================
$csvOutput = $flaggedUsers | ForEach-Object {
    [PSCustomObject]@{
        DisplayName  = $_.DisplayName
        UPN          = $_.UPN
        RiskScore    = $_.RiskScore
        RiskTier     = $_.RiskTier
        FlaggedByMSFT = $_.FlaggedByMSFT
        Downloads    = $_.DownloadCount
        Deletions    = $_.DeleteCount
        AfterHours   = $_.AfterHoursCount
        Findings     = $_.Findings -join " | "
    }
}

$csvPath = ".\M365-InsiderThreat-Report.csv"
$csvOutput | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "[+] CSV saved: $csvPath" -ForegroundColor Green

# ===========================
#  HTML REPORT
# ===========================
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$userRows = ""
foreach ($u in $flaggedUsers) {
    $tierColor = switch ($u.RiskTier) {
        "CRITICAL" { "#c00"    }
        "HIGH"     { "#e65c00" }
        "MEDIUM"   { "#b38600" }
        default    { "#107c10" }
    }
    $findingsHtml = ($u.Findings -join "<br>")
    $msftBadge    = if ($u.FlaggedByMSFT) { "<span style='background:#fde7e9;color:#c00;padding:2px 6px;border-radius:4px;font-size:0.75rem;font-weight:bold'>MSFT FLAG</span>" } else { "" }
    $userRows += "<tr><td><strong>$($u.DisplayName)</strong><br><span style='color:#888;font-size:0.8rem'>$($u.UPN)</span></td><td style='color:$tierColor;font-weight:bold;font-size:1.2rem'>$($u.RiskScore)</td><td style='color:$tierColor;font-weight:bold'>$($u.RiskTier) $msftBadge</td><td>$($u.DownloadCount)</td><td>$($u.DeleteCount)</td><td>$($u.AfterHoursCount)</td><td style='font-size:0.78rem;line-height:1.6'>$findingsHtml</td></tr>"
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>M365 Insider Threat Detection Report</title>
<style>
  body     { font-family: Segoe UI, Tahoma, sans-serif; padding: 2rem; background: #f4f6f9; color: #333; }
  h1       { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 0.5rem; }
  h2       { color: #0078d4; margin-top: 2rem; }
  .summary { display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }
  .card    { background: white; border-radius: 8px; padding: 1rem 1.5rem; min-width: 110px;
             box-shadow: 0 2px 6px rgba(0,0,0,0.08); text-align: center; }
  .card h3 { margin: 0; font-size: 2rem; }
  .card p  { margin: 0.3rem 0 0; font-size: 0.82rem; color: #666; }
  table    { width: 100%; border-collapse: collapse; background: white; border-radius: 8px;
             overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.08); margin-bottom: 2rem; }
  th       { background: #0078d4; color: white; padding: 11px 14px; text-align: left; font-size: 0.88rem; }
  td       { padding: 9px 14px; border-bottom: 1px solid #eee; font-size: 0.85rem; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td      { background: #f0f6ff; }
  .safe-note { background: #dff6dd; border-left: 4px solid #107c10; padding: 0.75rem 1rem;
               border-radius: 4px; margin-bottom: 1.5rem; font-size: 0.88rem; }
  footer   { margin-top: 2rem; font-size: 0.8rem; color: #999; border-top: 1px solid #ddd; padding-top: 1rem; }
</style>
</head>
<body>
<h1>Microsoft 365 Insider Threat Detection Report</h1>
<p>Generated: $timestamp | Analysis window: Last $lookbackDays days | Users analyzed: $($allUsers.Count)</p>
<div class="safe-note">Read-only audit using Microsoft Graph API. No user accounts, policies, or configurations were modified.</div>

<div class="summary">
  <div class="card"><h3 style="color:#c00">$critCount</h3><p>CRITICAL</p></div>
  <div class="card"><h3 style="color:#e65c00">$highCount</h3><p>HIGH</p></div>
  <div class="card"><h3 style="color:#b38600">$medCount</h3><p>MEDIUM</p></div>
  <div class="card"><h3 style="color:#107c10">$lowCount</h3><p>LOW</p></div>
  <div class="card"><h3>$($flaggedUsers.Count)</h3><p>Total Flagged</p></div>
  <div class="card"><h3>$($allUsers.Count)</h3><p>Users Analyzed</p></div>
</div>

<h2>Flagged Users - Behavioral Risk Analysis</h2>
<table>
<thead>
  <tr><th>User</th><th>Risk Score</th><th>Risk Tier</th><th>Downloads</th><th>Deletions</th><th>After Hours</th><th>Behavioral Findings</th></tr>
</thead>
<tbody>$userRows</tbody>
</table>

<h2>Detection Methodology</h2>
<table>
<thead><tr><th>Check</th><th>Trigger</th><th>Base Score</th></tr></thead>
<tbody>
  <tr><td>External Mail Forwarding</td><td>Forwarding or inbox rule detected</td><td>80 (+20 if created within 7 days)</td></tr>
  <tr><td>Bulk File Download</td><td>100+ file downloads in window</td><td>60 (+10 per additional 50 files)</td></tr>
  <tr><td>After-Hours Activity</td><td>5+ sign-ins outside 6am-8pm</td><td>20 (+15 if new location)</td></tr>
  <tr><td>Mass File Deletion</td><td>50+ file deletions in window</td><td>70 (+20 if near role change)</td></tr>
  <tr><td>Impossible Travel</td><td>Two countries within 2 hours</td><td>90</td></tr>
  <tr><td>Dormant Account Active</td><td>Account inactive 60+ days now active</td><td>50 (+30 if privileged)</td></tr>
  <tr><td>Failed Then Successful Login</td><td>5+ failures then success</td><td>60 (+20 unfamiliar IP)</td></tr>
  <tr><td>Privilege Escalation</td><td>Role added to account</td><td>40 (+30 if self-assigned)</td></tr>
  <tr><td>Microsoft Identity Protection Flag</td><td>Flagged by MSFT as risky</td><td>20-80 by severity</td></tr>
  <tr><td>Admin Role Removed + Download</td><td>Role removed then 20+ downloads within 48hrs</td><td>85</td></tr>
</tbody>
</table>

<footer>Generated by M365-InsiderThreat.ps1 | Read-only audit | No tenant changes made | Analysis window: $lookbackDays days</footer>
</body>
</html>
"@

$htmlPath = ".\M365-InsiderThreat-Report.html"
$html | Out-File $htmlPath -Encoding UTF8
Write-Host "[+] HTML report saved and opening: $htmlPath" -ForegroundColor Green
Start-Process $htmlPath

Write-Host "`n[DONE] Insider threat detection complete." -ForegroundColor Cyan
Write-Host "  Users flagged : $($flaggedUsers.Count)"
Write-Host "  CRITICAL      : $critCount"
Write-Host "  HIGH          : $highCount"
Write-Host "  CSV           : $csvPath"
Write-Host "  HTML          : $htmlPath`n"