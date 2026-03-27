function Test-MFAStatus {
    Write-Host "`n[Identity Audit] Checking MFA registration..." -ForegroundColor Cyan

    try {
        $users = Get-MgUser -All -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to retrieve users: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $usersWithoutMFA = @()
    $usersWithMFA = @()
    $usersLookupFailed = @()

    foreach ($user in $users) {
        try {
            $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop

            if ($methods.Count -le 1) {
                $usersWithoutMFA += $user.UserPrincipalName
            }
            else {
                $usersWithMFA += $user.UserPrincipalName
            }
        }
        catch {
            $usersLookupFailed += $user.UserPrincipalName
            Write-Host "Could not retrieve methods for $($user.UserPrincipalName)" -ForegroundColor Yellow
        }
    }

    Write-Host "`nTotal Users: $($users.Count)"
    Write-Host "Users WITH MFA methods: $($usersWithMFA.Count)" -ForegroundColor Green
    Write-Host "Users WITHOUT MFA methods: $($usersWithoutMFA.Count)" -ForegroundColor Red
    Write-Host "Users with lookup failures: $($usersLookupFailed.Count)" -ForegroundColor Yellow

    if ($usersWithoutMFA.Count -gt 0) {
        Write-Host "`nUsers without MFA methods:" -ForegroundColor Yellow
        $usersWithoutMFA | ForEach-Object { Write-Host $_ }
    }

    if ($usersLookupFailed.Count -gt 0) {
        Write-Host "`nUsers with lookup failures:" -ForegroundColor Yellow
        $usersLookupFailed | ForEach-Object { Write-Host $_ }
    }
}