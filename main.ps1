. .\modules\connect.ps1
. .\modules\audit_identity.ps1
. .\modules\audit_ca.ps1

$connected = Connect-M365

if ($connected) {
    Test-MFAStatus
    Test-ConditionalAccessPolicies
}
else {
    Write-Host "Stopping script because Graph connection was not established." -ForegroundColor Red
}