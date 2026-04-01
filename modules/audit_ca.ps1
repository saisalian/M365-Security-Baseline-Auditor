function Get-CAClassification {
    param (
        [Parameter(Mandatory = $true)]
        $Policy
    )

    $categories = @()
    $reasons = @()

    $policyName = $Policy.DisplayName

    $grantControls  = @($Policy.GrantControls.BuiltInControls)
    $clientAppTypes = @($Policy.Conditions.ClientAppTypes)

    $includePlatforms = @()
    if ($null -ne $Policy.Conditions.Platforms) {
        $includePlatforms = @($Policy.Conditions.Platforms.IncludePlatforms)
    }

    $includeLocations = @()
    if ($null -ne $Policy.Conditions.Locations) {
        $includeLocations = @($Policy.Conditions.Locations.IncludeLocations)
    }

    $userRiskLevels = @($Policy.Conditions.UserRiskLevels)
    $signInRiskLvls = @($Policy.Conditions.SignInRiskLevels)

    $usersIncludeGuestsOrExternal = $null
    if ($null -ne $Policy.Conditions.Users) {
        $usersIncludeGuestsOrExternal = $Policy.Conditions.Users.IncludeGuestsOrExternalUsers
    }

    $sessionControls = $Policy.SessionControls

    # 1. MFA Enforcement
    if ($grantControls -contains "mfa") {
        $categories += "MFA Enforcement"
        $reasons += "Grant controls include MFA."
    }

    # 2. Legacy Authentication Control (refined)
    $hasExchangeActiveSync = $clientAppTypes -contains "exchangeActiveSync"
    $hasOtherClientApps    = $clientAppTypes -contains "other"

    $hasDeviceRequirement = (
        $grantControls -contains "compliantDevice" -or
        $grantControls -contains "domainJoinedDevice"
    )

    $nameLooksLegacy = $false
    if ($policyName -match "(?i)legacy|basic auth|block legacy") {
        $nameLooksLegacy = $true
    }

    if (
        $hasExchangeActiveSync -or
        ($hasOtherClientApps -and $nameLooksLegacy -and -not $hasDeviceRequirement)
    ) {
        $categories += "Legacy Authentication Control"
        $reasons += "Targets legacy client app types with legacy-auth indicators."
    }

    # 3. Device / BYOD Control
    if ($hasDeviceRequirement) {
        $categories += "Device / BYOD Control"
        $reasons += "Uses device-related grant controls."
    }

    # 4. Location-Based Control
    $meaningfulLocations = @(
        $includeLocations | Where-Object {
            $_ -and
            $_ -ne "All" -and
            $_ -ne "AllTrusted" -and
            $_ -ne "AllCompliantNetworkLocations"
        }
    )

    if ($meaningfulLocations.Count -gt 0) {
        $categories += "Location-Based Control"
        $reasons += "Targets specific named or defined locations."
    }

    # 5. Risk-Based Control
    if ($userRiskLevels.Count -gt 0 -or $signInRiskLvls.Count -gt 0) {
        $categories += "Risk-Based Control"
        $reasons += "Uses user risk or sign-in risk conditions."
    }

    # 6. Guest / External Access Control
    $guestConfigured = $false

    if ($null -ne $usersIncludeGuestsOrExternal) {
        if ($usersIncludeGuestsOrExternal.IncludeGuestsOrExternalUsers -eq $true) {
            $guestConfigured = $true
        }
        elseif ($usersIncludeGuestsOrExternal.GuestOrExternalUserTypes) {
            $guestConfigured = $true
        }
    }

    if ($guestConfigured) {
        $categories += "Guest / External Access Control"
        $reasons += "Explicitly targets guest or external users."
    }

    # 7. Session Control (refined)
    $hasSessionControl = $false

    if ($null -ne $sessionControls) {
        # Sign-in frequency
        if ($null -ne $sessionControls.SignInFrequency) {
            $signInFrequency = $sessionControls.SignInFrequency

            if (
                $null -ne $signInFrequency.Value -or
                $null -ne $signInFrequency.Type -or
                $null -ne $signInFrequency.AuthenticationType -or
                $null -ne $signInFrequency.FrequencyInterval
            ) {
                $hasSessionControl = $true
                $reasons += "Uses sign-in frequency session control."
            }
        }

        # Persistent browser
        if ($null -ne $sessionControls.PersistentBrowser) {
            $persistentBrowser = $sessionControls.PersistentBrowser

            if ($null -ne $persistentBrowser.Mode) {
                $hasSessionControl = $true
                $reasons += "Uses persistent browser session control."
            }
        }

        # Application enforced restrictions
        if ($null -ne $sessionControls.ApplicationEnforcedRestrictions) {
            $appRestrictions = $sessionControls.ApplicationEnforcedRestrictions

            if ($appRestrictions.IsEnabled -eq $true) {
                $hasSessionControl = $true
                $reasons += "Uses application enforced restrictions."
            }
        }

        # Defender for Cloud Apps session control
        if ($null -ne $sessionControls.CloudAppSecurity) {
            $cloudAppSecurity = $sessionControls.CloudAppSecurity

            if (
                $null -ne $cloudAppSecurity.CloudAppSecurityType -and
                $cloudAppSecurity.CloudAppSecurityType -ne "none"
            ) {
                $hasSessionControl = $true
                $reasons += "Uses Defender for Cloud Apps session control."
            }
        }
    }

    if ($hasSessionControl) {
        $categories += "Session Control"
    }

    # Confidence
    $uniqueCategories = $categories | Sort-Object -Unique
    switch ($uniqueCategories.Count) {
        0 { $confidence = "Low" }
        1 { $confidence = "Low" }
        2 { $confidence = "Medium" }
        default { $confidence = "High" }
    }

    if ($uniqueCategories.Count -eq 0) {
        $uniqueCategories = @("Unclassified")
        $reasons += "No explicit classification rules were triggered."
        $confidence = "Low"
    }

    return [PSCustomObject]@{
        PolicyName = $Policy.DisplayName
        State      = $Policy.State
        Categories = $uniqueCategories -join "; "
        Confidence = $confidence
        Reasoning  = ($reasons | Sort-Object -Unique) -join " "
    }
}

function Test-ConditionalAccessPolicies {
    Write-Host "`n[Conditional Access Audit] Classifying policies..." -ForegroundColor Cyan

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

    $results = foreach ($policy in $policies) {
        Get-CAClassification -Policy $policy
    }

    Write-Host "Total Conditional Access Policies: $($results.Count)" -ForegroundColor Green
    Write-Host ""

    foreach ($result in $results) {
        Write-Host "Policy: $($result.PolicyName)" -ForegroundColor Yellow
        Write-Host "  State: $($result.State)"
        Write-Host "  Categories: $($result.Categories)"
        Write-Host "  Confidence: $($result.Confidence)"
        Write-Host "  Reasoning: $($result.Reasoning)"
        Write-Host ""
    }

    Write-Host "[Conditional Access Summary]" -ForegroundColor Cyan

    $allCategories = $results | ForEach-Object {
        $_.Categories -split "; "
    }

    $categorySummary = $allCategories |
        Group-Object |
        Sort-Object Count -Descending

    foreach ($item in $categorySummary) {
        Write-Host "$($item.Name): $($item.Count)" -ForegroundColor Green
    }
}