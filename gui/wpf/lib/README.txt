This folder holds the three WebView2 SDK DLLs downloaded by Setup-WebView2.ps1.

Run Setup-WebView2.ps1 once to populate it:

    pwsh -File ..\Setup-WebView2.ps1

Files that will appear here after setup:
    Microsoft.Web.WebView2.Core.dll
    Microsoft.Web.WebView2.Wpf.dll
    WebView2Loader.dll

Do NOT commit these DLLs to source control — they are fetched at setup time.
