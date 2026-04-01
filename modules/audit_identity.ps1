function Get-AccountType {
    param (
        [Parameter(Mandatory = $true)]
        $User
    )

    $upn = $User.UserPrincipalName
    $displayName = $User.DisplayName
    $userType = $User.UserType
    $mailNickname = $User.MailNickname

    # Guest accounts
    if ($userType -eq "Guest" -or $upn -like "*#EXT#*") {
        return "Guest"
    }

    # Breakglass / emergency-style accounts
    if (
        $upn -match "(?i)breakglass|emergency" -or
        $displayName -match "(?i)breakglass|emergency"
    ) {
        return "Breakglass"
    }

    # Shared / service-style account heuristics
    if (
        $upn -match "(?i)^info@|^hr@|^legal@|^finance@|^accounts@|^admin@|^support@" -or
        $upn -match "(?i)package_" -or
        $displayName -match "(?i)shared|service|mailbox" -or
        $mailNickname -match "(?i)shared|service"
    ) {
        return "Service/Shared"
    }

    return "Member"
}

function Test-MFAStatus {
    Write-Host "`n[Identity Audit] Checking MFA registration by account type..." -ForegroundColor Cyan

    try {
        $users = Get-MgUser -All -Property "id,displayName,userPrincipalName,userType,mailNickname" -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to retrieve users: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $results = @()

    foreach ($user in $users) {
        $accountType = Get-AccountType -User $user
        $mfaStatus = "Unknown"

        try {
            $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop

            if ($methods.Count -le 1) {
                $mfaStatus = "No MFA Methods"
            }
            else {
                $mfaStatus = "Has MFA Methods"
            }
        }
        catch {
            $mfaStatus = "Lookup Failed"
        }

        $results += [PSCustomObject]@{
            DisplayName       = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            UserType          = $user.UserType
            AccountType       = $accountType
            MFAStatus         = $mfaStatus
        }
    }

    Write-Host "`nTotal Users: $($results.Count)" -ForegroundColor Green

    $accountTypes = @("Member", "Guest", "Service/Shared", "Breakglass")

    foreach ($type in $accountTypes) {
        $subset = $results | Where-Object { $_.AccountType -eq $type }

        if ($subset.Count -gt 0) {
            $withMFA = ($subset | Where-Object { $_.MFAStatus -eq "Has MFA Methods" }).Count
            $withoutMFA = ($subset | Where-Object { $_.MFAStatus -eq "No MFA Methods" }).Count
            $lookupFailed = ($subset | Where-Object { $_.MFAStatus -eq "Lookup Failed" }).Count

            Write-Host "`n$type Accounts:" -ForegroundColor Yellow
            Write-Host "  Total: $($subset.Count)"
            Write-Host "  With MFA Methods: $withMFA" -ForegroundColor Green
            Write-Host "  Without MFA Methods: $withoutMFA" -ForegroundColor Red
            Write-Host "  Lookup Failed: $lookupFailed" -ForegroundColor Yellow
        }
    }

    $membersWithoutMFA = $results | Where-Object {
        $_.AccountType -eq "Member" -and $_.MFAStatus -eq "No MFA Methods"
    }

    $guestsWithoutMFA = $results | Where-Object {
        $_.AccountType -eq "Guest" -and $_.MFAStatus -eq "No MFA Methods"
    }

    $serviceWithoutMFA = $results | Where-Object {
        $_.AccountType -eq "Service/Shared" -and $_.MFAStatus -eq "No MFA Methods"
    }

    $breakglassWithoutMFA = $results | Where-Object {
        $_.AccountType -eq "Breakglass" -and $_.MFAStatus -eq "No MFA Methods"
    }

    if ($membersWithoutMFA.Count -gt 0) {
        Write-Host "`nMembers without MFA methods:" -ForegroundColor Yellow
        $membersWithoutMFA | ForEach-Object { Write-Host "  • $($_.UserPrincipalName)" }
    }

    if ($guestsWithoutMFA.Count -gt 0) {
        Write-Host "`nGuests without MFA methods:" -ForegroundColor Yellow
        $guestsWithoutMFA | ForEach-Object { Write-Host "  • $($_.UserPrincipalName)" }
    }

    if ($serviceWithoutMFA.Count -gt 0) {
        Write-Host "`nService/Shared accounts without MFA methods:" -ForegroundColor Yellow
        $serviceWithoutMFA | ForEach-Object { Write-Host "  • $($_.UserPrincipalName)" }
    }

    if ($breakglassWithoutMFA.Count -gt 0) {
        Write-Host "`nBreakglass accounts without MFA methods:" -ForegroundColor Yellow
        $breakglassWithoutMFA | ForEach-Object { Write-Host "  • $($_.UserPrincipalName)" }
    }

    Write-Host "`nNote: MFA registration readiness is being measured here, not full enforcement. Conditional Access and account purpose must also be considered." -ForegroundColor DarkYellow
}