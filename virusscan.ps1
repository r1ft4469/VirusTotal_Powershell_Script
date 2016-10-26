#requires -version 3.0

  #==============================================#
  # LogRhythm Labs                               #
  # VirusTotal - Process Check SmartResponse(TM) #
  # greg . foss [at] logrhythm . com             #
  # v0.1  --  November 2015                      #
  #==============================================#

# Copyright 2015 LogRhythm Inc.   
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.  You may obtain a copy of the License at;
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.

#=======================================================================================
# Original script from: https://psvirustotal.codeplex.com/
# Modified to scan processes, email reports, run remotely, and integrate with the SIEM
#=======================================================================================

[CmdLetBinding()]
param( 
    [switch]$remote = $false,
    [switch]$sendEmail = $false,
    [string]$VTApiKey,
    [string]$smtpServer,
    [string]$emailFrom,
    [string]$emailTo,
    [string]$processName,
    [string]$processID,
    [string]$file,
    [string]$target,
    [string]$username,
    [string]$password
)

function Virus-Total {

<#
.NAME
    Virus-Total

.SYNOPSIS
    PowerShell VirusTotal API Integration and Automated Alerting

.DESCRIPTION
    This script is meant to integrate with security infrastructure, such as a SIEM in order to automate the analysis of new processes and/or files

.NOTES
    This tool is designed to be executed from a LogRhythm SmartResponse(TM) on remote hosts via the LogRhythm agent, remotely using the LogRhythm SIEM, or locally/remotely as a standalone PowerShell script.
    The safest way to run this script is locally, however remote execution is possible. Realize this will open the system up to additional risk...

.EXAMPLE
Check a file against VirusTotal using their API
    PS C:\> .\vt-process-check.ps1 -file "C:\Users\taco\Desktop\eicar.txt"

.EXAMPLE
Check a running process against VirusTotal using their API
    Process ID
        PS C:\> .\vt-process-check.ps1 -processID 1234   
    Process Name (less accurate than process ID if there are multiple processes with the same name)
        PS C:\> .\vt-process-check.ps1 -processName chrome
        
.EXAMPLE
Remote Execution
    PS C:\> .\vt-process-check.ps1 -remote -target [computer] [arguments - EX: -processID -file -username -password]
    Caveats:
        You will need to ensure that psremoting and unsigned execution is enabled on the remote host.  // dangerous to leave enabled!
        Be careful, this may inadvertently expose administrative credentials when authenticating to a remote compromised host.

.EXAMPLE
Send results via email
    PS C:\> .\vt-process-check.ps1 -processID 1234 -smtpServer [127.0.0.1] -emailTo [greg.foss[at]logrhythm.com] -emailFrom [virustotal[at]logrhythm.com]
    
.OUTPUTS
    -Host IP Address
    -Host Name
    -Scan Date
    -Process Name
    -Process ID
    -Associated File
    -SHA256 Hash
    -VirusTotal Link
#>

function Get-Hash(
    [System.IO.FileInfo] $file = $(Throw 'Usage: Get-Hash [System.IO.FileInfo]'), 
    [String] $hashType = 'sha256')
{
  $stream = $null;  
  [string] $result = $null;
  $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($hashType )
  $stream = $file.OpenRead();
  $hashByteArray = $hashAlgorithm.ComputeHash($stream);
  $stream.Close();

  trap
  {
    if ($stream -ne $null) { $stream.Close(); }
    break;
  }

  # Convert the hash to Hex
  $hashByteArray | foreach { $result += $_.ToString("X2") }
  return $result
}

function Get-Bytes([String] $str) {
    $bytes = New-Object Byte[] ($str.Length * 2)
    #[System.Buffer]::BlockCopy($str.ToCharArray(), 0, $bytes, 0, $bytes.Length)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($str)
    return $bytes
}

function Get-VTReport {
    [CmdletBinding()]
    Param( 
    [Parameter(Mandatory=$false)][ValidateNotNull()][String] $VTApiKey,
    [Parameter(ParameterSetName="hash", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash,
    [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][System.IO.FileInfo] $file,
    [Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][Uri] $uri,
    [Parameter(ParameterSetName="ipaddress", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $ip,
    [Parameter(ParameterSetName="domain", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $domain
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/report'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/report'
        $IPUri = 'http://www.virustotal.com/vtapi/v2/ip-address/report'
        $DomainUri = 'http://www.virustotal.com/vtapi/v2/domain/report'
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = @{}

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $h = Get-Hash -file $file
            Write-Verbose -Message ("FileHash:" + $h)
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $h; apikey = $VTApiKey}
            }
        "hash" {            
            $u = $fileUri
            $method = 'POST'
            $body = @{ resource = $hash; apikey = $VTApiKey}
            }
        "uri" {
            $u = $UriUri
            $method = 'POST'
            $body = @{ url = $uri; apikey = $VTApiKey}
            }
        "ipaddress" {
            $u = $IPUri
            $method = 'GET'
            $body = @{ ip = $ip; apikey = $VTApiKey}
        }
        "domain" {            
            $u = $DomainUri
            $method = 'GET'
            $body = @{ domain = $domain; apikey = $VTApiKey}}
        }        

        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

function Invoke-VTScan {
    [CmdletBinding()]
    Param( 
    [Parameter(Mandatory=$false)][ValidateNotNull()]
        [String] $VTApiKey,
    [Parameter(ParameterSetName="file", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [System.IO.FileInfo] $file,
    [Parameter(ParameterSetName="uri", ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Uri] $uri
    )
    Begin {
        $fileUri = 'https://www.virustotal.com/vtapi/v2/file/scan'
        $UriUri = 'https://www.virustotal.com/vtapi/v2/url/scan'
        [byte[]]$CRLF = 13, 10
    }
    Process {
        [String] $h = $null
        [String] $u = $null
        [String] $method = $null
        $body = New-Object System.IO.MemoryStream

        switch ($PSCmdlet.ParameterSetName) {
        "file" { 
            $u = $fileUri
            $method = 'POST'
            $boundary = [Guid]::NewGuid().ToString().Replace('-','')
            $ContentType = 'multipart/form-data; boundary=' + $boundary
            $b2 = Get-Bytes ('--' + $boundary)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-Bytes ('Content-Disposition: form-data; name="apikey"'))
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-Bytes $VTApiKey)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = (Get-Bytes ('Content-Disposition: form-data; name="file"; filename="' + $file.Name + '";'))
            $body.Write($b, 0, $b.Length)
            $body.Write($CRLF, 0, $CRLF.Length)            
            $b = (Get-Bytes 'Content-Type:application/octet-stream')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($CRLF, 0, $CRLF.Length)
            
            $b = [System.IO.File]::ReadAllBytes($file.FullName)
            $body.Write($b, 0, $b.Length)

            $body.Write($CRLF, 0, $CRLF.Length)
            $body.Write($b2, 0, $b2.Length)
            
            $b = (Get-Bytes '--')
            $body.Write($b, 0, $b.Length)
            
            $body.Write($CRLF, 0, $CRLF.Length)
            
                
            Invoke-RestMethod -Method $method -Uri $u -ContentType $ContentType -Body $body.ToArray()
            }
        "uri" {
            $h = $uri
            $u = $UriUri
            $method = 'POST'
            $body = @{ url = $uri; apikey = $VTApiKey}
            Invoke-RestMethod -Method $method -Uri $u -Body $body
            }            
        }                        
    }    
}

function Invoke-VTRescan {
 [CmdletBinding()]
    Param( 
    [Parameter(Mandatory=$true)][ValidateNotNull()][String] $VTApiKey,
    [Parameter(Mandatory=$true, ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)][String] $hash
    )
    Process {
        $u = 'https://www.virustotal.com/vtapi/v2/file/rescan'
        $method = 'POST'
        $body = @{ resource = $hash; apikey = $VTApiKey}
        return Invoke-RestMethod -Method $method -Uri $u -Body $body
    }    
}

#=======================================================================================
# ACTIONS
#=======================================================================================

# Get the file location
if ( $processName ) {
    $separator = "."
    $processName = $processName.split($separator)
    $file = @(Get-Process -Name $processName[0] | Select-Object Path | sort -Unique).Path
    $processID = @(Get-Process -Name $processName[0] | sort -Unique).Id
} 
if ( $processID ) {
    $file = @(Get-Process -Id $processID | Select-Object Path | sort -Unique).Path
    $processName = @(Get-Process -Id $processID).ProcessName
} 
if ( $file ) {
    $hizzash = Get-Hash -file $file
}
if (-Not ( $processName )) {
    if (-Not ( $processID )) {
        if (-Not ( $file )) {
            Write-Host ""
            write-Host "Specify a process (-processName / -processID) or file (-file) and try again..."
            Exit 1
        }
    }
}
$report = Get-VTReport -hash $hizzash -VTApiKey $VTApiKey

$ip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$computerName = (gi env:\Computername).Value
$reportDate = $report.scan_date
$hits = $report.positives
$link = $report.permalink
$shaSum = $report.sha256
$detection = $report.scans | findstr 'True' | foreach {$_ + "<br />"}

#=======================================================================================
# REPORTING
#=======================================================================================

if ( $report.response_code -eq 0 ) {
    Write-Host ""
    $newScan = Invoke-VTScan -file $file -VTApiKey $VTApiKey
    $shaSum = $newScan.sha256
    $link = $newScan.permalink
    $messageTitle = "<h2 style='font:Lucida Console,Monaco,monospace;color:#1F497D;'><strong>Sample Submitted to VirusTotal</strong></h2>"
    $message = @"
New Sample!<br /><br />
This file has been submitted to VirusTotal for analysis...<br />
<br />
<strong>IP</strong>         :  $ip<br /><br />
<strong>Host</strong>       :  $computerName<br /><br />
<strong>Process ID</strong> :  $processID<br /><br />
<strong>Process</strong>    :  $processName<br /><br />
<strong>File</strong>       :  $file<br /><br />
<strong>SHA256</strong>     :  $shaSum<br /><br />
"@
        $message -replace '<br />|<strong>|</strong>',''
        Write-Host "Link       :  $link"

} else {
    Write-Host ""
    if ( $report.positives -gt 0 ) {
        $messageTitle = "<h2 style='font:Lucida Console,Monaco,monospace;color:#780000;'><strong>Malware Detected!</strong></h2>"
        $message = @"
Scan Results:<br /><br />
<strong>$hits Anti-Virus engines have flagged this sample as malicious</strong><br />
<br />
<strong>IP</strong>         :  $ip<br /><br />
<strong>Host</strong>       :  $computerName<br /><br />
<strong>Scan Date</strong>  :  $reportDate<br /><br />
<strong>Process ID</strong> :  $processID<br /><br />
<strong>Process</strong>    :  $processName<br /><br />
<strong>File</strong>       :  $file<br /><br />
<strong>SHA256</strong>     :  $shaSum<br /><br />
<strong>AV Engines that detected the threat:</strong><br />
$detection
<br />
"@
        $message -replace '<br />|<strong>|</strong>',''
        Write-Host ""
        Write-Host "Link       :  $link"

    } else {
        Write-Host ""
        $messageTitle = "<h2 style='font:Lucida Console,Monaco,monospace;color:#006633;'><strong>No Malware Detected</strong></h2>"
        $message = @"
Scan Results:<br /><br />
<strong>No Anti-Virus engines have flagged this sample as malicious</strong><br />
<br />
<strong>IP</strong>         :  $ip<br /><br />
<strong>Host</strong>       :  $computerName<br /><br />
<strong>Scan Date</strong>  :  $reportDate<br /><br />
<strong>Process ID</strong> :  $processID<br /><br />
<strong>Process</strong>    :  $processName<br /><br />
<strong>File</strong>       :  $file<br /><br />
<strong>SHA256</strong>     :  $shaSum<br /><br />
"@
        $message -replace '<br />|<strong>|</strong>',''
        Write-Host "Link       :  $link"
    }
}

#=======================================================================================
# EMAIL
#=======================================================================================

if ( $smtpServer ) {
    function sendEmail {
        $msg = New-Object System.Net.Mail.MailMessage
        $smtp = New-Object System.Net.Mail.SMTPClient($smtpServer)
        $msg.From = $emailFrom
        $msg.To.Add($emailTo)
        $msg.Subject = "VirusTotal Scan Results"
        $msg.Body = @"
<html><head></head><body>
<center><br />
<p style='font:16px Lucida Console,Monaco,monospace;'>
$messageTitle
</center>
$message
<strong>Link</strong>      :  <a href='$link'>$link</a><br />
</p>
</body></html>
"@
        $msg.IsBodyHTML = $true
        $smtp.Send($msg)
    }
    Write-Host ""
    Write-Host "     Sending email using SMTP Server: $smtpServer"
    sendEmail
    Write-Host "     Message From : $emailFrom"
    Write-Host "     Message To : $emailTo"
    Write-Host "     Subject : VirusTotal Scan Results"
    Write-Host ""
}
}

#=======================================================================================
# REMOTE ANALYSIS
#=======================================================================================

if ( $remote -eq $false ) {
Virus-Total
} else {
    $hostnameCheck = "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?$"
    if (-not ($target -match $hostnameCheck)) {
        Write-Host "That's not a hostname..."
        Exit 1
    }
    try {
        if (-Not ($password)) {
            $cred = Get-Credential
        } Else {
            $securePass = ConvertTo-SecureString -string $password -AsPlainText -Force
            $cred = New-Object -typename System.Management.Automation.PSCredential -argumentlist $username, $securePass
        }
        $scriptName = $MyInvocation.MyCommand.Name
        $content = type $scriptName
                
        if ( $processName ) {
            Invoke-Command -ScriptBlock {
                param ($content,$scriptName,$processName,$processID,$file,$VTApiKey,$smtpServer,$emailFrom,$emailTo)
                while (Test-Path \vt.ps1) {
                    rm \vt.ps1
                }
                $content >> \vt.ps1
                C:\vt.ps1 -processName $processName -VTApiKey $VTApiKey -emailFrom $emailFrom -emailTo $emailTo -smtpServer $smtpServer
                rm C:\vt.ps1
            } -ArgumentList @($content,$scriptName,$processName,$processID,$file,$VTApiKey,$smtpServer,$emailFrom,$emailTo) -ComputerName $target -Credential $cred
        }

        if ( $processID ) {
            Invoke-Command -ScriptBlock {
                param ($content,$scriptName,$processName,$processID,$file,$VTApiKey,$smtpServer,$emailFrom,$emailTo)
                while (Test-Path \vt.ps1) {
                    rm \vt.ps1
                }
                $content >> \vt.ps1
                C:\vt.ps1 -processID $processID -VTApiKey $VTApiKey -emailFrom $emailFrom -emailTo $emailTo -smtpServer $smtpServer
                rm C:\vt.ps1
            } -ArgumentList @($content,$scriptName,$processName,$processID,$file,$VTApiKey,$smtpServer,$emailFrom,$emailTo) -ComputerName $target -Credential $cred
        }

        if ( $file ) {
            Invoke-Command -ScriptBlock {
                param ($content,$scriptName,$file,$VTApiKey,$smtpServer,$emailFrom,$emailTo)
                while (Test-Path \vt.ps1) {
                    rm \vt.ps1
                }
                $content >> \vt.ps1
                C:\vt.ps1 -file $file -VTApiKey $VTApiKey -emailFrom $emailFrom -emailTo $emailTo -smtpServer $smtpServer
                rm C:\vt.ps1
            } -ArgumentList @($content,$scriptName,$file,$VTApiKey,$smtpServer,$emailFrom,$emailTo) -ComputerName $target -Credential $cred
        }

    } catch {
            Write-Host "Access Denied..."
            Exit 1
    }
}