# Windows TPM EK Certificate Extraction

The AMD fTPM and many other Windows TPM implementations do not automatically provision the EK certificate to an accessible location. The cert exists in the Windows certificate store but requires specific registry access to extract.

## Step 1 — Confirm TPM presence and manufacturer

```powershell
Get-Tpm
tpmtool getdeviceinformation
```

Confirm `TpmPresent: True`, `TpmVersion: 2.0`, and note `ManufacturerId`.

## Step 2 — Find the EK cert in the registry

```powershell
reg query "HKLM\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement" /s
```

Look for subkeys under `EKCertStoreECC` or `EKCertStore`. Note the thumbprint key name.

## Step 3 — Extract the blob structure

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI\Endorsement\EKCertStoreECC\Certificates\<THUMBPRINT>"
$blob = (Get-ItemProperty -Path $regPath).Blob

# Inspect blob length and header
Write-Host "Blob length: $($blob.Length)"
($blob[0..39] | ForEach-Object { $_.ToString("X2") }) -join " "
```

## Step 4 — Find the DER cert start

The DER cert always starts with `30 82`. Find the offset:

```powershell
$derStart = -1
for ($i = 0; $i -lt 60; $i++) {
    if ($blob[$i] -eq 0x30 -and $blob[$i+1] -eq 0x82) {
        $derStart = $i
        break
    }
}

if ($derStart -eq -1) {
    Write-Host "DER start not found in first 60 bytes"
} else {
    Write-Host "DER start at offset $derStart"
    $certBytes = $blob[$derStart..($blob.Length - 1)]
    New-Item -ItemType Directory -Force -Path C:\temp | Out-Null
    [System.IO.File]::WriteAllBytes("C:\temp\ek.cer", $certBytes)
    Write-Host "Cert saved to C:\temp\ek.cer"
}
```

## Step 5 — Parse the cert

```powershell
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\temp\ek.cer")
$cert | Format-List Subject, Issuer, NotBefore, NotAfter, Thumbprint
$cert.Extensions | ForEach-Object {
    Write-Host $_.Oid.FriendlyName
    Write-Host $_.Format($true)
}
```

## Step 6 — Fetch the intermediate and root from AIA

The AIA extension in the EK cert contains the URL for the manufacturer's intermediate CA cert. Extract it from the `Authority Information Access` extension output and fetch:

```powershell
# Replace URL with the AIA URL from the cert extensions
Invoke-WebRequest -Uri "http://ftpm.amd.com/pki/aia/<HASH>" -OutFile "C:\temp\intermediate.cer"
Invoke-WebRequest -Uri "http://ftpm.amd.com/pki/aia/<ROOT_HASH>" -OutFile "C:\temp\root.cer"
```

## Step 7 — Export all three certs as hex for fixture capture

```powershell
Write-Host "=== EK_CERT ==="
[System.IO.File]::ReadAllBytes("C:\temp\ek.cer") | ForEach-Object { $_.ToString("X2") } | Write-Host -NoNewline
Write-Host ""

Write-Host "=== INTERMEDIATE_CERT ==="
[System.IO.File]::ReadAllBytes("C:\temp\intermediate.cer") | ForEach-Object { $_.ToString("X2") } | Write-Host -NoNewline
Write-Host ""

Write-Host "=== ROOT_CERT ==="
[System.IO.File]::ReadAllBytes("C:\temp\root.cer") | ForEach-Object { $_.ToString("X2") } | Write-Host -NoNewline
Write-Host ""
```

## Known issues

- **AMD fTPM**: EK cert is in `EKCertStoreECC` not `EKCertStore` — look for the ECC variant first.
- The blob header format is not documented by Microsoft — DER start offset varies, use the `30 82` search method.
- AMD provisioning URLs confirmed: `ftpm.amd.com/pki/aia/` — other manufacturers vary.
- Intel PTT from 11th gen: EK cert chain is embedded in NV storage, accessible via the `tpmdiagnostics` tool.
- If `EKCertStore` subkeys are empty: run `Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-HASCertRetr"` and wait 30 seconds.

## Dotwave Windows client

The Dotwave Windows app automates this entire process using the `tss-esapi` Rust crate via the Windows TBS socket. Users never need to run these PowerShell commands. This documentation is for ZK-PKI developers adding new manufacturer intermediate hashes to `KNOWN_MANUFACTURER_INTERMEDIATES`.
