Write-Host "Cleaning up __pycache__ directories..." -ForegroundColor Cyan
Get-ChildItem -Path . -Recurse -Filter "__pycache__" -Directory | ForEach-Object {
    Write-Host "Removing $($_.FullName)" -ForegroundColor Yellow
    Remove-Item -Path $_.FullName -Recurse -Force
}
Write-Host "Done! You can now load the extension." -ForegroundColor Green
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 