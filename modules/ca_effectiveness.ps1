function Test-CAEffectiveness {
    Write-Host "`n[Conditional Access Effectiveness Assessment]" -ForegroundColor Cyan

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to retrieve Conditional Access policies for effectiveness analysis: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Host "No Conditional Access policies found." -ForegroundColor Red
        return
    }

    # ---------- Helpers ----------
    function Get-PolicyNameMatches {
        param(
            [array]$PolicySet,
            [string[]]$Patterns
        )

        return $PolicySet | Where-Object {
            $name = $_.DisplayName
            foreach ($pattern in $Patterns) {
                if ($name -match $pattern) { return $true }
            }
            return $false
        }
    }

    function Get-EnabledPolicies {
        param([array]$PolicySet)
        return $PolicySet | Where-Object { $_.State -eq "enabled" }
    }

    function Get-ReportOnlyPolicies {
        param([array]$PolicySet)
        return $PolicySet | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
    }

    # ---------- Policy buckets ----------
    $mfaPolicies = $policies | Where-Object {
        @($_.GrantControls.BuiltInControls) -contains "mfa"
    }

    $legacyPolicies = $policies | Where-Object {
        $clientApps = @($_.Conditions.ClientAppTypes)
        ($clientApps -contains "exchangeActiveSync") -or
        ($_.DisplayName -match "(?i)legacy|basic auth|block legacy")
    }

    $adminPolicies = Get-PolicyNameMatches -PolicySet $policies -Patterns @("(?i)admin", "(?i)azure management")
    $guestPolicies = Get-PolicyNameMatches -PolicySet $policies -Patterns @("(?i)guest", "(?i)external")
    $disabledPolicies = $policies | Where-Object { $_.State -eq "disabled" }

    # ---------- MFA Assessment ----------
    Write-Host "`nMFA Enforcement:" -ForegroundColor Yellow

    $enabledMFAPolicies = Get-EnabledPolicies -PolicySet $mfaPolicies
    $reportOnlyMFAPolicies = Get-ReportOnlyPolicies -PolicySet $mfaPolicies

    $allUserMFAPolicies = $mfaPolicies | Where-Object {
        $_.DisplayName -match "(?i)all users"
    }

    $enabledAllUserMFAPolicies = Get-EnabledPolicies -PolicySet $allUserMFAPolicies
    $reportOnlyAllUserMFAPolicies = Get-ReportOnlyPolicies -PolicySet $allUserMFAPolicies

    if ($enabledMFAPolicies.Count -gt 0) {
        Write-Host "✔ MFA-related Conditional Access policies detected: $($enabledMFAPolicies.Count)" -ForegroundColor Green
    }
    else {
        Write-Host "❌ No enabled MFA-related Conditional Access policies detected." -ForegroundColor Red
    }

    if ($enabledAllUserMFAPolicies.Count -gt 0) {
        Write-Host "✔ At least one MFA policy for all users is enabled." -ForegroundColor Green
    }
    elseif ($reportOnlyAllUserMFAPolicies.Count -gt 0) {
        Write-Host "⚠ MFA policy for all users exists but is in report-only mode." -ForegroundColor Yellow
    }
    else {
        Write-Host "⚠ No obvious enabled MFA policy for all users was detected by current heuristics." -ForegroundColor Yellow
    }

    # ---------- Legacy Authentication Assessment ----------
    Write-Host "`nLegacy Authentication:" -ForegroundColor Yellow

    $enabledLegacyPolicies = Get-EnabledPolicies -PolicySet $legacyPolicies
    $reportOnlyLegacyPolicies = Get-ReportOnlyPolicies -PolicySet $legacyPolicies

    if ($enabledLegacyPolicies.Count -gt 0) {
        Write-Host "✔ Enabled legacy authentication blocking-related policy detected." -ForegroundColor Green
        $enabledLegacyPolicies | ForEach-Object { Write-Host "  • $($_.DisplayName)" }
    }
    elseif ($reportOnlyLegacyPolicies.Count -gt 0) {
        Write-Host "⚠ Legacy authentication control exists but is only in report-only mode." -ForegroundColor Yellow
        $reportOnlyLegacyPolicies | ForEach-Object { Write-Host "  • $($_.DisplayName)" }
    }
    else {
        Write-Host "❌ No enabled legacy authentication blocking-related policy detected." -ForegroundColor Red
    }

    if ($legacyPolicies.Count -gt 1) {
        Write-Host "⚠ Multiple legacy authentication-related policies detected. Review for duplicates or old disabled copies." -ForegroundColor Yellow
    }

    # ---------- Admin Protection ----------
    Write-Host "`nAdmin Protection:" -ForegroundColor Yellow

    $enabledAdminPolicies = Get-EnabledPolicies -PolicySet $adminPolicies

    if ($enabledAdminPolicies.Count -gt 0) {
        Write-Host "✔ Admin-focused Conditional Access protection detected." -ForegroundColor Green
        $enabledAdminPolicies | ForEach-Object { Write-Host "  • $($_.DisplayName)" }
    }
    else {
        Write-Host "⚠ No obvious enabled admin-focused Conditional Access policy detected by current heuristics." -ForegroundColor Yellow
    }

    # ---------- Guest Protection ----------
    Write-Host "`nGuest / External Access Protection:" -ForegroundColor Yellow

    $enabledGuestPolicies = Get-EnabledPolicies -PolicySet $guestPolicies

    if ($enabledGuestPolicies.Count -gt 0) {
        Write-Host "✔ Guest / external access protection policy detected." -ForegroundColor Green
        $enabledGuestPolicies | ForEach-Object { Write-Host "  • $($_.DisplayName)" }
    }
    else {
        Write-Host "⚠ No obvious enabled guest / external access Conditional Access policy detected." -ForegroundColor Yellow
    }

    # ---------- Policy Hygiene ----------
    Write-Host "`nPolicy Hygiene:" -ForegroundColor Yellow

    if ($disabledPolicies.Count -gt 0) {
        Write-Host "⚠ Disabled Conditional Access policies found: $($disabledPolicies.Count)" -ForegroundColor Yellow
        $disabledPolicies | ForEach-Object { Write-Host "  • $($_.DisplayName)" }
    }
    else {
        Write-Host "✔ No disabled Conditional Access policies found." -ForegroundColor Green
    }

    # ---------- Overall Assessment ----------
    Write-Host "`nOverall Assessment:" -ForegroundColor Yellow

    $riskFindings = 0

    if ($enabledMFAPolicies.Count -eq 0) { $riskFindings++ }
    if ($enabledAllUserMFAPolicies.Count -eq 0) { $riskFindings++ }
    if ($enabledLegacyPolicies.Count -eq 0) { $riskFindings++ }
    if ($enabledAdminPolicies.Count -eq 0) { $riskFindings++ }

    if ($riskFindings -eq 0) {
        Write-Host "✔ Overall Conditional Access posture appears strong based on current checks." -ForegroundColor Green
    }
    elseif ($riskFindings -le 2) {
        Write-Host "⚠ Overall Conditional Access posture appears moderate. Some important controls need review." -ForegroundColor Yellow
    }
    else {
        Write-Host "❌ Overall Conditional Access posture appears weak based on current checks." -ForegroundColor Red
    }

    Write-Host "`nNote: This module uses practical heuristics and does not yet perform full scope validation of policy targeting, exclusions, or cloud app coverage." -ForegroundColor DarkYellow
}