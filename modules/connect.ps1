function Connect-M365 {
    Write-Host "Microsoft 365 Tenant Connection" -ForegroundColor Cyan

    $tenantInput = Read-Host "Enter Tenant ID or primary domain (example: contoso.onmicrosoft.com)"
    
    if ([string]::IsNullOrWhiteSpace($tenantInput)) {
        Write-Host "Tenant input cannot be empty." -ForegroundColor Red
        return
    }

    Import-Module Microsoft.Graph

    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Connecting to tenant: $tenantInput" -ForegroundColor Yellow
    Write-Host "Use an InPrivate/incognito browser window if needed." -ForegroundColor Yellow

    Connect-MgGraph `
        -TenantId $tenantInput `
        -Scopes "User.Read.All","Policy.Read.All","Directory.Read.All" `
        -UseDeviceAuthentication `
        -ContextScope Process `
        -NoWelcome

    $context = Get-MgContext
    $org = Get-MgOrganization

    if ($null -ne $context) {
        Write-Host "Connected successfully!" -ForegroundColor Green
        Write-Host "Account: $($context.Account)"
        Write-Host "Tenant ID: $($context.TenantId)"
        Write-Host "Tenant Name: $($org.DisplayName)"
    }
    else {
        Write-Host "Connection failed." -ForegroundColor Red
    }
}