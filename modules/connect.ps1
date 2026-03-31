function Connect-M365 {
    Write-Host "Microsoft 365 Tenant Connection" -ForegroundColor Cyan

    $tenantInput = Read-Host "Enter Tenant ID or primary domain (example: contoso.onmicrosoft.com)"

    if ([string]::IsNullOrWhiteSpace($tenantInput)) {
        Write-Host "Tenant input cannot be empty." -ForegroundColor Red
        return $false
    }

    Import-Module Microsoft.Graph

    # Clear any previous Graph session
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Connecting to tenant: $tenantInput" -ForegroundColor Yellow

    try {
        Connect-MgGraph `
            -TenantId $tenantInput `
            -Scopes "User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All","Policy.Read.All","Policy.Read.ConditionalAccess" `
            -ContextScope Process `
            -NoWelcome `
            -ErrorAction Stop

        $context = Get-MgContext -ErrorAction Stop

        if ($null -ne $context) {
            Write-Host "Connected successfully!" -ForegroundColor Green
            Write-Host "Account: $($context.Account)"
            Write-Host "Tenant ID: $($context.TenantId)"
            return $true
        }
        else {
            Write-Host "Connection failed: no Graph context found." -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Connection failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}