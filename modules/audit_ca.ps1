function Test-ConditionalAccessPolicies {
    Write-Host "`n[Conditional Access Audit] Checking policies..." -ForegroundColor Cyan

    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to retrieve Conditional Access policies: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if (-not $policies -or $policies.Count -eq 0) {
        Write-Host "No Conditional Access policies found." -ForegroundColor Red
        return
    }

    Write-Host "Total Conditional Access Policies: $($policies.Count)" -ForegroundColor Green

    $mfaPolicies = @()
    $legacyAuthPolicies = @()

    foreach ($policy in $policies) {
        Write-Host "- $($policy.DisplayName)"

        $grantControls = $policy.GrantControls.BuiltInControls
        $clientAppTypes = $policy.Conditions.ClientAppTypes

        if ($grantControls -contains "mfa") {
            $mfaPolicies += $policy.DisplayName
        }

        if ($clientAppTypes -contains "exchangeActiveSync" -or $clientAppTypes -contains "other") {
            if ($policy.State -eq "enabled") {
                $legacyAuthPolicies += $policy.DisplayName
            }
        }
    }

    Write-Host "`nPolicies requiring MFA: $($mfaPolicies.Count)" -ForegroundColor Green
    if ($mfaPolicies.Count -gt 0) {
        $mfaPolicies | ForEach-Object { Write-Host "  • $_" }
    }

    Write-Host "`nPolicies potentially blocking legacy authentication: $($legacyAuthPolicies.Count)" -ForegroundColor Yellow
    if ($legacyAuthPolicies.Count -gt 0) {
        $legacyAuthPolicies | ForEach-Object { Write-Host "  • $_" }
    }
}