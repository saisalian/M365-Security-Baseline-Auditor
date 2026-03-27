function Connect-M365 {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan

    Import-Module Microsoft.Graph

    Write-Host "Starting Graph authentication..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "User.Read.All","Policy.Read.All","Directory.Read.All" -NoWelcome

    Write-Host "Authentication command completed." -ForegroundColor Yellow

    $context = Get-MgContext

    if ($null -ne $context) {
        Write-Host "Connected successfully!" -ForegroundColor Green
        Write-Host "Account: $($context.Account)"
        Write-Host "Tenant ID: $($context.TenantId)"
        Write-Host "Scopes: $($context.Scopes -join ', ')"
    }
    else {
        Write-Host "No Graph context found." -ForegroundColor Red
    }
}