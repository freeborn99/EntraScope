$lib     = 'C:\Users\notmy\.gemini\antigravity\scratch\EntraScope\gui\wpf\lib'
$nupkgUrl = 'https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/1.0.4078.44'
$zip      = Join-Path $lib 'wv2.zip'
$extract  = Join-Path $lib 'wv2_tmp'

Write-Host 'Downloading...'
Invoke-WebRequest $nupkgUrl -OutFile $zip -TimeoutSec 60
Expand-Archive $zip $extract -Force

# Use net5.0-windows Wpf DLL (compatible with PS7/.NET 7+ WPF v10)
# Core DLL from netcoreapp3.0 (no WPF dependency - works fine)
# WebView2Loader.dll from build/native/x64

$srcCore  = Join-Path $extract 'lib_manual\netcoreapp3.0\Microsoft.Web.WebView2.Core.dll'
$srcWpf   = Join-Path $extract 'lib_manual\net5.0-windows10.0.17763.0\Microsoft.Web.WebView2.Wpf.dll'
$srcLoad  = Join-Path $extract 'build\native\x64\WebView2Loader.dll'

Copy-Item $srcCore  (Join-Path $lib 'Microsoft.Web.WebView2.Core.dll') -Force
Copy-Item $srcWpf   (Join-Path $lib 'Microsoft.Web.WebView2.Wpf.dll')  -Force
Copy-Item $srcLoad  (Join-Path $lib 'WebView2Loader.dll')              -Force

Remove-Item $zip     -Force
Remove-Item $extract -Recurse -Force

Write-Host 'Done:'
Get-ChildItem $lib -Filter '*.dll' | ForEach-Object {
    Write-Host "  $($_.Name)  ($([Math]::Round($_.Length/1KB)) KB)"
}
