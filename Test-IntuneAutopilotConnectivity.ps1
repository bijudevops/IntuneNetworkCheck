<#
.SYNOPSIS
    Validates Microsoft Intune + Windows Autopilot (Hybrid Azure AD Join) network requirements during OOBE/ESP.
.DESCRIPTION
    This script performs comprehensive network connectivity testing to detect common causes of ESP stalls 
    and Hybrid Join failures. It verifies connectivity and non-inspection to required Microsoft endpoints.
    
    The script can run in both admin and SYSTEM context, with the -AsSystem parameter allowing it to
    schedule itself as a SYSTEM task for ESP scenarios.
.PARAMETER OutputPath
    Path for the CSV output file. Default: C:\ProgramData\IntuneConnectivity-<timestamp>.csv
.PARAMETER AsSystem
    Schedule a one-time Scheduled Task to run the same script as SYSTEM immediately and write the CSV.
.PARAMETER JsonPath
    Optional path for JSON report output.
.PARAMETER TimeoutMs
    Timeout in milliseconds for network tests. Default: 5000
.PARAMETER Retries
    Number of retry attempts for failed tests. Default: 1
.PARAMETER Parallel
    Test endpoints in parallel if PowerShell 7+, else fallback to sequential.
.PARAMETER AdditionalEndpoints
    Additional FQDNs to test beyond the default critical endpoints.
.EXAMPLE
    .\Test-IntuneAutopilotConnectivity.ps1
.EXAMPLE
    .\Test-IntuneAutopilotConnectivity.ps1 -OutputPath C:\Temp\IntuneConnectivity.csv
.EXAMPLE
    .\Test-IntuneAutopilotConnectivity.ps1 -AsSystem
.EXAMPLE
    .\Test-IntuneAutopilotConnectivity.ps1 -JsonPath C:\Temp\IntuneConnectivity.json -TimeoutMs 7000 -Retries 2
.NOTES
    Author: Intune Network Connectivity Validator
    Version: 1.0
    Requires: PowerShell 5.1 or higher
    Compatible with: Windows 10/11, Windows Server 2016+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$AsSystem,
    
    [Parameter(Mandatory = $false)]
    [string]$JsonPath,
    
    [Parameter(Mandatory = $false)]
    [int]$TimeoutMs = 5000,
    
    [Parameter(Mandatory = $false)]
    [int]$Retries = 1,
    
    [Parameter(Mandatory = $false)]
    [switch]$Parallel,
    
    [Parameter(Mandatory = $false)]
    [string[]]$AdditionalEndpoints = @()
)

# Script configuration
$ScriptName = "Test-IntuneAutopilotConnectivity"
$DefaultOutputPath = "C:\ProgramData\IntuneConnectivity-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$CriticalEndpoints = @(
    "dm.microsoft.com",
    "manage.microsoft.com", 
    "enterpriseregistration.windows.net",
    "device.login.microsoftonline.com",
    "login.microsoftonline.com",
    "ztd.dds.microsoft.com",
    "cs.dds.microsoft.com",
    "www.msftconnecttest.com"
)

# Global variables for results
$Global:TestResults = @()
$Global:StartTime = Get-Date

# Function to add test result
function Add-TestResult {
    param(
        [string]$Category,
        [string]$Item,
        [string]$SubItem = "",
        [ValidateSet("OK", "FAIL", "WARN", "INFO")]
        [string]$Status,
        [string]$Data = ""
    )
    
    $result = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Item = $Item
        SubItem = $SubItem
        Status = $Status
        Data = $Data
    }
    
    $Global:TestResults += $result
}

# Function to test if running as SYSTEM
function Test-SystemContext {
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $isSystem = $currentUser.Name -eq "NT AUTHORITY\SYSTEM"
        Add-TestResult -Category "Environment" -Item "User Context" -Status "INFO" -Data "Running as: $($currentUser.Name)"
        return $isSystem
    }
    catch {
        Add-TestResult -Category "Environment" -Item "User Context" -Status "WARN" -Data "Unable to determine user context: $($_.Exception.Message)"
        return $false
    }
}

# Function to get environment information
function Get-EnvironmentInfo {
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        Add-TestResult -Category "Environment" -Item "OS Version" -Status "INFO" -Data "$($osInfo.Caption) Build $($osInfo.BuildNumber)"
        
        $psVersion = $PSVersionTable.PSVersion
        Add-TestResult -Category "Environment" -Item "PowerShell Version" -Status "INFO" -Data "$psVersion"
        
        $computerName = $env:COMPUTERNAME
        Add-TestResult -Category "Environment" -Item "Computer Name" -Status "INFO" -Data $computerName
        
        $domain = $env:USERDOMAIN
        Add-TestResult -Category "Environment" -Item "Domain" -Status "INFO" -Data $domain
    }
    catch {
        Add-TestResult -Category "Environment" -Item "Environment Info" -Status "WARN" -Data "Error gathering environment info: $($_.Exception.Message)"
    }
}

# Function to check firewall profiles
function Test-FirewallProfiles {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        
        foreach ($firewallProfile in $profiles) {
            $profileName = $firewallProfile.Name
            $enabled = $firewallProfile.Enabled
            $defaultOutbound = $firewallProfile.DefaultOutboundAction
            
            Add-TestResult -Category "Firewall" -Item "Profile: $profileName" -Status "INFO" -Data "Enabled: $enabled, Default Outbound: $defaultOutbound"
            
            if ($enabled -and $defaultOutbound -eq "Block") {
                Add-TestResult -Category "Firewall" -Item "Profile: $profileName" -Status "WARN" -Data "Profile enabled with blocked outbound - may cause connectivity issues"
            }
        }
    }
    catch {
        Add-TestResult -Category "Firewall" -Item "Firewall Profiles" -Status "WARN" -Data "Error checking firewall profiles: $($_.Exception.Message)"
    }
}

# Function to detect proxy configuration
function Test-ProxyConfiguration {
    try {
        # Check WinHTTP proxy
        $winhttpProxy = netsh winhttp show proxy 2>$null | Out-String
        Add-TestResult -Category "Proxy" -Item "WinHTTP Proxy" -Status "INFO" -Data $winhttpProxy.Trim()
        
        # Check if proxy is configured
        if ($winhttpProxy -match "Proxy Server\(s\):\s+(\S+)") {
            $proxyServer = $matches[1]
            Add-TestResult -Category "Proxy" -Item "Proxy Detection" -Status "INFO" -Data "Explicit proxy detected: $proxyServer"
            
            # Check if it's a known inspection proxy
            if ($proxyServer -match "(zscaler|paloalto|checkpoint|fortinet|cisco|bluecoat|websense)", "IgnoreCase") {
                Add-TestResult -Category "Proxy" -Item "Proxy Detection" -Status "WARN" -Data "Known SSL inspection proxy detected: $proxyServer"
            }
        }
        elseif ($winhttpProxy -match "Direct access") {
            Add-TestResult -Category "Proxy" -Item "Proxy Detection" -Status "INFO" -Data "Direct access (no proxy)"
        }
        else {
            Add-TestResult -Category "Proxy" -Item "Proxy Detection" -Status "WARN" -Data "Unknown proxy configuration"
        }
        
        # Check WinINET proxy for comparison
        try {
            $regProxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -ErrorAction Stop
            if ($regProxy.ProxyServer) {
                Add-TestResult -Category "Proxy" -Item "WinINET Proxy" -Status "INFO" -Data "User proxy: $($regProxy.ProxyServer)"
            }
        }
        catch {
            Add-TestResult -Category "Proxy" -Item "WinINET Proxy" -Status "INFO" -Data "No user proxy configured"
        }
    }
    catch {
        Add-TestResult -Category "Proxy" -Item "Proxy Configuration" -Status "WARN" -Data "Error checking proxy configuration: $($_.Exception.Message)"
    }
}

# Function to resolve DNS
function Test-DnsResolution {
    param([string]$Fqdn)
    
    try {
        $dnsResult = Resolve-DnsName -Name $Fqdn -Type A -ErrorAction Stop
        $ipAddresses = ($dnsResult.IPAddress | Where-Object { $_ -ne $null }) -join ", "
        
        if ($ipAddresses) {
            Add-TestResult -Category "DNS" -Item $Fqdn -Status "OK" -Data "Resolved to: $ipAddresses"
            return $ipAddresses
        }
        else {
            Add-TestResult -Category "DNS" -Item $Fqdn -Status "FAIL" -Data "No A records found"
            return $null
        }
    }
    catch {
        Add-TestResult -Category "DNS" -Item $Fqdn -Status "FAIL" -Data "DNS resolution failed: $($_.Exception.Message)"
        return $null
    }
}

# Function to test TCP connectivity
function Test-TcpConnectivity {
    param(
        [string]$Fqdn,
        [string]$IpAddress,
        [int]$Port = 443
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectResult = $tcpClient.BeginConnect($IpAddress, $Port, $null, $null)
        
        if ($connectResult.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $tcpClient.EndConnect($connectResult)
            $tcpClient.Close()
            Add-TestResult -Category "TCP" -Item "$Fqdn`:$Port" -Status "OK" -Data "Connected to $IpAddress"
            return $true
        }
        else {
            $tcpClient.Close()
            Add-TestResult -Category "TCP" -Item "$Fqdn`:$Port" -Status "FAIL" -Data "Connection timeout to $IpAddress"
            return $false
        }
    }
    catch {
        Add-TestResult -Category "TCP" -Item "$Fqdn`:$Port" -Status "FAIL" -Data "Connection failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to test TLS handshake
function Test-TlsHandshake {
    param(
        [string]$Fqdn,
        [string]$IpAddress,
        [int]$Port = 443
    )
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($IpAddress, $Port)
        
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false)
        $sslStream.AuthenticateAsClient($Fqdn)
        
        $cert = $sslStream.RemoteCertificate
        if ($null -eq $cert) {
            $tcpClient.Close()
            Add-TestResult -Category "TLS" -Item "$Fqdn`:$Port" -Status "FAIL" -Data "No certificate received from server"
            return $false
        }
        
        $subject = $cert.Subject
        $issuer = $cert.Issuer
        $notAfter = $cert.NotAfter
        
        $tcpClient.Close()
        
        # Check for SSL inspection
        $inspectionIndicators = @("zscaler", "paloalto", "checkpoint", "fortinet", "cisco", "bluecoat", "websense", "ssl-inspection", "proxy")
        $isInspection = $false
        
        foreach ($indicator in $inspectionIndicators) {
            if ($issuer -match $indicator -or $subject -match $indicator) {
                $isInspection = $true
                break
            }
        }
        
        if ($isInspection) {
            Add-TestResult -Category "TLS" -Item "$Fqdn`:$Port" -Status "WARN" -Data "SSL inspection detected - Subject: $subject, Issuer: $issuer, Expires: $notAfter"
        }
        else {
            Add-TestResult -Category "TLS" -Item "$Fqdn`:$Port" -Status "OK" -Data "Subject: $subject, Issuer: $issuer, Expires: $notAfter"
        }
        
        return $true
    }
    catch {
        Add-TestResult -Category "TLS" -Item "$Fqdn`:$Port" -Status "FAIL" -Data "TLS handshake failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to test endpoint with retries
function Test-Endpoint {
    param(
        [string]$Fqdn,
        [int]$MaxRetries = 1
    )
    
    $attempt = 0
    $success = $false
    
    while ($attempt -le $MaxRetries -and -not $success) {
        $attempt++
        
        # DNS Resolution
        $ipAddresses = Test-DnsResolution -Fqdn $Fqdn
        if (-not $ipAddresses) {
            if ($attempt -gt $MaxRetries) {
                Add-TestResult -Category "Summary" -Item $Fqdn -Status "FAIL" -Data "DNS resolution failed after $MaxRetries attempts"
            }
            continue
        }
        
        # Get first IP for testing
        $firstIp = ($ipAddresses -split ", ")[0]
        
        # TCP Connectivity
        $tcpSuccess = Test-TcpConnectivity -Fqdn $Fqdn -IpAddress $firstIp
        if (-not $tcpSuccess) {
            if ($attempt -gt $MaxRetries) {
                Add-TestResult -Category "Summary" -Item $Fqdn -Status "FAIL" -Data "TCP connectivity failed after $MaxRetries attempts"
            }
            continue
        }
        
        # TLS Handshake
        $tlsSuccess = Test-TlsHandshake -Fqdn $Fqdn -IpAddress $firstIp
        if ($tlsSuccess) {
            $success = $true
            Add-TestResult -Category "Summary" -Item $Fqdn -Status "OK" -Data "All tests passed"
        }
        elseif ($attempt -gt $MaxRetries) {
            Add-TestResult -Category "Summary" -Item $Fqdn -Status "FAIL" -Data "TLS handshake failed after $MaxRetries attempts"
        }
    }
}

# Function to get M365 endpoints (optional)
function Get-M365Endpoints {
    try {
        $endpointUrl = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7&ServiceAreas=MEM"
        $response = Invoke-RestMethod -Uri $endpointUrl -Method Get -TimeoutSec 10 -ErrorAction Stop
        
        $memEndpoints = $response | Where-Object { $_.serviceArea -eq "MEM" } | Select-Object -First 5
        
        if ($memEndpoints) {
            Add-TestResult -Category "M365 Endpoints" -Item "MEM Service" -Status "INFO" -Data "Retrieved $($memEndpoints.Count) MEM endpoints"
            return $memEndpoints.urls
        }
        else {
            Add-TestResult -Category "M365 Endpoints" -Item "MEM Service" -Status "WARN" -Data "No MEM endpoints found in response"
            return @()
        }
    }
    catch {
        Add-TestResult -Category "M365 Endpoints" -Item "MEM Service" -Status "WARN" -Data "Failed to retrieve M365 endpoints: $($_.Exception.Message)"
        return @()
    }
}

# Function to export results
function Export-Results {
    param(
        [string]$CsvPath,
        [string]$JsonPath = ""
    )
    
    try {
        # Export CSV
        $Global:TestResults | Export-Csv -Path $CsvPath -NoTypeInformation -ErrorAction Stop
        Add-TestResult -Category "Export" -Item "CSV Export" -Status "OK" -Data "Results exported to: $CsvPath"
        
        # Export JSON if requested
        if ($JsonPath) {
            $jsonData = $Global:TestResults | ConvertTo-Json -Depth 3
            Set-Content -Path $JsonPath -Value $jsonData -ErrorAction Stop
            Add-TestResult -Category "Export" -Item "JSON Export" -Status "OK" -Data "Results exported to: $JsonPath"
        }
        
        return $true
    }
    catch {
        Add-TestResult -Category "Export" -Item "Export" -Status "FAIL" -Data "Export failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to create SYSTEM task
function New-SystemTask {
    try {
        $scriptPath = $PSCommandPath
        
        
        
        
        
        = Split-Path -Parent $scriptPath
        $scriptName = Split-Path -Leaf $scriptPath
        
        # Copy script to ProgramData
        $programDataPath = "C:\ProgramData\$ScriptName"
        if (-not (Test-Path $programDataPath)) {
            New-Item -ItemType Directory -Path $programDataPath -Force | Out-Null
        }
        
        $destScriptPath = Join-Path $programDataPath $scriptName
        Copy-Item -Path $scriptPath -Destination $destScriptPath -Force
        
        # Create scheduled task
        $taskName = "$ScriptName-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$destScriptPath`" -OutputPath `"$DefaultOutputPath`""
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description "One-time SYSTEM task for $ScriptName"
        Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
        
        Add-TestResult -Category "System Task" -Item "Task Creation" -Status "OK" -Data "Scheduled task '$taskName' created successfully"
        Add-TestResult -Category "System Task" -Item "Script Location" -Status "INFO" -Data "Script copied to: $destScriptPath"
        
        Write-Host "SYSTEM task '$taskName' scheduled successfully. Script will run as SYSTEM and output to: $DefaultOutputPath" -ForegroundColor Green
        Write-Host "Current process will exit. Check the output file for results." -ForegroundColor Yellow
        
        return $true
    }
    catch {
        Add-TestResult -Category "System Task" -Item "Task Creation" -Status "FAIL" -Data "Failed to create SYSTEM task: $($_.Exception.Message)"
        Write-Host "Failed to create SYSTEM task: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to display summary
function Show-Summary {
    $totalTests = $Global:TestResults.Count
    $passedTests = ($Global:TestResults | Where-Object { $_.Status -eq "OK" }).Count
    $failedTests = ($Global:TestResults | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnTests = ($Global:TestResults | Where-Object { $_.Status -eq "WARN" }).Count
    
    Write-Host "`n=== CONNECTIVITY TEST SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Total Tests: $totalTests" -ForegroundColor White
    Write-Host "PASSED: $passedTests" -ForegroundColor Green
    Write-Host "FAILED: $failedTests" -ForegroundColor Red
    Write-Host "WARNINGS: $warnTests" -ForegroundColor Yellow
    
    if ($failedTests -gt 0) {
        Write-Host "`nCRITICAL ISSUES DETECTED:" -ForegroundColor Red
        $Global:TestResults | Where-Object { $_.Status -eq "FAIL" } | ForEach-Object {
            Write-Host "  - $($_.Category): $($_.Item) - $($_.Data)" -ForegroundColor Red
        }
    }
    
    if ($warnTests -gt 0) {
        Write-Host "`nWARNINGS:" -ForegroundColor Yellow
        $Global:TestResults | Where-Object { $_.Status -eq "WARN" } | ForEach-Object {
            Write-Host "  - $($_.Category): $($_.Item) - $($_.Data)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nResults exported to: $OutputPath" -ForegroundColor Green
    if ($JsonPath) {
        Write-Host "JSON report exported to: $JsonPath" -ForegroundColor Green
    }
}

# Main execution
function Main {
    Write-Host "Microsoft Intune + Windows Autopilot Network Connectivity Validator" -ForegroundColor Cyan
    Write-Host "Version 1.0 - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray
    
    # Handle -AsSystem parameter
    if ($AsSystem) {
        if (Test-SystemContext) {
            Write-Host "Already running as SYSTEM. Proceeding with tests..." -ForegroundColor Yellow
        }
        else {
            if (New-SystemTask) {
                exit 0
            }
            else {
                Write-Host "Failed to create SYSTEM task. Continuing as current user..." -ForegroundColor Yellow
            }
        }
    }
    
    # Set output path
    if (-not $OutputPath) {
        $OutputPath = $DefaultOutputPath
    }
    
    # Environment checks
    Write-Host "Gathering environment information..." -ForegroundColor Yellow
    Get-EnvironmentInfo
    Test-SystemContext | Out-Null
    
    # Network configuration checks
    Write-Host "Checking network configuration..." -ForegroundColor Yellow
    Test-FirewallProfiles
    Test-ProxyConfiguration
    
    # Get endpoints to test
    $endpointsToTest = $CriticalEndpoints + $AdditionalEndpoints
    
    # Get M365 endpoints if possible
    Write-Host "Retrieving M365 endpoints..." -ForegroundColor Yellow
    $m365Endpoints = Get-M365Endpoints
    if ($m365Endpoints) {
        $endpointsToTest += $m365Endpoints
    }
    
    # Test endpoints
    Write-Host "Testing endpoint connectivity..." -ForegroundColor Yellow
    
    if ($Parallel -and $PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "Running tests in parallel (PowerShell 7+)" -ForegroundColor Green
        $jobs = @()
        
        foreach ($endpoint in $endpointsToTest) {
            $jobs += Start-Job -ScriptBlock {
                param($Fqdn, $TimeoutMs, $Retries)
                
                # Import functions into job
                function Test-DnsResolution { param([string]$Fqdn) try { $dnsResult = Resolve-DnsName -Name $Fqdn -Type A -ErrorAction Stop; $ipAddresses = ($dnsResult.IPAddress | Where-Object { $_ -ne $null }) -join ", "; if ($ipAddresses) { return $ipAddresses } else { return $null } } catch { return $null } }
                function Test-TcpConnectivity { param([string]$Fqdn, [string]$IpAddress, [int]$Port = 443) try { $tcpClient = New-Object System.Net.Sockets.TcpClient; $connectResult = $tcpClient.BeginConnect($IpAddress, $Port, $null, $null); if ($connectResult.AsyncWaitHandle.WaitOne($using:TimeoutMs)) { $tcpClient.EndConnect($connectResult); $tcpClient.Close(); return $true } else { $tcpClient.Close(); return $false } } catch { return $false } }
                function Test-TlsHandshake { param([string]$Fqdn, [string]$IpAddress, [int]$Port = 443) try { $tcpClient = New-Object System.Net.Sockets.TcpClient; $tcpClient.Connect($IpAddress, $Port); $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false); $sslStream.AuthenticateAsClient($Fqdn); $cert = $sslStream.RemoteCertificate; if ($null -eq $cert) { $tcpClient.Close(); return $false }; $tcpClient.Close(); return $true } catch { return $false } }
                
                $result = @{
                    Fqdn = $Fqdn
                    DnsSuccess = $false
                    TcpSuccess = $false
                    TlsSuccess = $false
                    IpAddress = $null
                }
                
                # DNS Resolution
                $ipAddresses = Test-DnsResolution -Fqdn $Fqdn
                if ($ipAddresses) {
                    $result.DnsSuccess = $true
                    $result.IpAddress = ($ipAddresses -split ", ")[0]
                    
                    # TCP Connectivity
                    $result.TcpSuccess = Test-TcpConnectivity -Fqdn $Fqdn -IpAddress $result.IpAddress
                    
                    # TLS Handshake
                    if ($result.TcpSuccess) {
                        $result.TlsSuccess = Test-TlsHandshake -Fqdn $Fqdn -IpAddress $result.IpAddress
                    }
                }
                
                return $result
            } -ArgumentList $endpoint, $TimeoutMs, $Retries
        }
        
        # Wait for all jobs to complete
        $results = $jobs | Wait-Job | Receive-Job
        $jobs | Remove-Job
        
        # Process results
        foreach ($result in $results) {
            if ($result.DnsSuccess) {
                Add-TestResult -Category "DNS" -Item $result.Fqdn -Status "OK" -Data "Resolved to: $($result.IpAddress)"
                
                if ($result.TcpSuccess) {
                    Add-TestResult -Category "TCP" -Item "$($result.Fqdn):443" -Status "OK" -Data "Connected to $($result.IpAddress)"
                    
                    if ($result.TlsSuccess) {
                        Add-TestResult -Category "TLS" -Item "$($result.Fqdn):443" -Status "OK" -Data "TLS handshake successful"
                        Add-TestResult -Category "Summary" -Item $result.Fqdn -Status "OK" -Data "All tests passed"
                    }
                    else {
                        Add-TestResult -Category "TLS" -Item "$($result.Fqdn):443" -Status "FAIL" -Data "TLS handshake failed"
                        Add-TestResult -Category "Summary" -Item $result.Fqdn -Status "FAIL" -Data "TLS handshake failed"
                    }
                }
                else {
                    Add-TestResult -Category "TCP" -Item "$($result.Fqdn):443" -Status "FAIL" -Data "Connection failed"
                    Add-TestResult -Category "Summary" -Item $result.Fqdn -Status "FAIL" -Data "TCP connectivity failed"
                }
            }
            else {
                Add-TestResult -Category "DNS" -Item $result.Fqdn -Status "FAIL" -Data "DNS resolution failed"
                Add-TestResult -Category "Summary" -Item $result.Fqdn -Status "FAIL" -Data "DNS resolution failed"
            }
        }
    }
    else {
        Write-Host "Running tests sequentially" -ForegroundColor Green
        foreach ($endpoint in $endpointsToTest) {
            Test-Endpoint -Fqdn $endpoint -MaxRetries $Retries
        }
    }
    
    # Export results
    Write-Host "Exporting results..." -ForegroundColor Yellow
    Export-Results -CsvPath $OutputPath -JsonPath $JsonPath
    
    # Display summary
    Show-Summary
}

# Script execution
try {
    Main
}
catch {
    Write-Host "Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Add-TestResult -Category "Script" -Item "Execution" -Status "FAIL" -Data "Script execution failed: $($_.Exception.Message)"
    
    # Try to export any results we have
    if ($Global:TestResults.Count -gt 0) {
        try {
            Export-Results -CsvPath $OutputPath -JsonPath $JsonPath
            Write-Host "Partial results exported to: $OutputPath" -ForegroundColor Yellow
        }
        catch {
            Write-Host "Failed to export partial results: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    exit 1
}
