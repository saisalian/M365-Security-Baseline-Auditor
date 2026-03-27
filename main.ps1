. .\modules\connect.ps1
. .\modules\audit_identity.ps1

$connected = Connect-M365

if ($connected) {
    Test-MFAStatus
}
else {
    Write-Host "Stopping script because Graph connection was not established." -ForegroundColor Red
}