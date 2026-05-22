param(
    [Parameter(Mandatory = $true)]
    [string]$VulnerableBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$ProtectedBaseUrl,

    [Parameter(Mandatory = $true)]
    [string]$ImdsVulnerable,

    [Parameter(Mandatory = $true)]
    [string]$ImdsProtected,

    [string]$AwsEndpointUrl = "http://localhost:4566",
    [string]$Region = "us-east-1",
    [string]$OutputDir = "artifacts/reports"
)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = "C:/Users/rvsvh/AppData/Local/Programs/Python/Python312/python.exe"

& $python -m scanner.cli `
    --vulnerable-base-url $VulnerableBaseUrl `
    --protected-base-url $ProtectedBaseUrl `
    --imds-vulnerable $ImdsVulnerable `
    --imds-protected $ImdsProtected `
    --aws-endpoint-url $AwsEndpointUrl `
    --region $Region `
    --output-dir $OutputDir