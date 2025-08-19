# Intune Network Connectivity Validator

A production-grade PowerShell script that validates Microsoft Intune + Windows Autopilot (Hybrid Azure AD Join) network requirements during OOBE/ESP (Enrollment Status Page).

## 🎯 Purpose

This tool detects common causes of ESP stalls and Hybrid Join failures by performing comprehensive network connectivity testing. It's designed for Windows/Intune engineers to quickly diagnose network issues that prevent successful device enrollment and Azure AD joining.

## ✨ Features

### Core Functionality
- **Environment Detection**: OS version, PowerShell version, user context, computer name, domain
- **Firewall Analysis**: Profile states and outbound policies
- **Proxy Detection**: WinHTTP vs WinINET, SSL inspection detection
- **DNS Resolution**: A record resolution for all endpoints
- **TCP Connectivity**: Port 443 reachability with timeout/retry logic
- **TLS Handshake**: Certificate validation and SSL inspection detection
- **Critical Endpoints**: All required Microsoft Intune/Autopilot endpoints
- **M365 Integration**: Dynamic MEM endpoint retrieval (optional)

### Advanced Capabilities
- **SYSTEM Context Support**: Full SYSTEM task scheduling for ESP scenarios
- **Parallel Testing**: PowerShell 7+ parallel execution with PS5.1 fallback
- **Comprehensive Reporting**: CSV and JSON output formats
- **Retry Logic**: Configurable retry attempts for network failures
- **SSL Inspection Detection**: Identifies known inspection proxies (Zscaler, Palo Alto, etc.)

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or higher (PowerShell 7+ recommended for parallel testing)
- Administrative privileges (for full functionality)

### Basic Usage
```powershell
# Download and run
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/bijudevops/IntuneNetworkCheck/master/Test-IntuneAutopilotConnectivity.ps1" -UseBasicParsing).Content

# Or clone the repository
git clone https://github.com/bijudevops/IntuneNetworkCheck.git
cd IntuneNetworkCheck
.\Test-IntuneAutopilotConnectivity.ps1
```

### Common Scenarios

#### Basic Network Validation
```powershell
.\Test-IntuneAutopilotConnectivity.ps1
```

#### Custom Output Location
```powershell
.\Test-IntuneAutopilotConnectivity.ps1 -OutputPath C:\Temp\IntuneConnectivity.csv
```

#### Run as SYSTEM (for ESP scenarios)
```powershell
.\Test-IntuneAutopilotConnectivity.ps1 -AsSystem
```

#### Advanced Configuration
```powershell
.\Test-IntuneAutopilotConnectivity.ps1 -JsonPath C:\Temp\IntuneConnectivity.json -TimeoutMs 7000 -Retries 2 -Parallel
```

## 📋 Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `OutputPath` | string | No | `C:\ProgramData\IntuneConnectivity-<timestamp>.csv` | Custom CSV output path |
| `AsSystem` | switch | No | `$false` | Schedule as SYSTEM task for ESP scenarios |
| `JsonPath` | string | No | None | Optional JSON report output |
| `TimeoutMs` | int | No | `5000` | Network timeout in milliseconds |
| `Retries` | int | No | `1` | Retry attempts for failed tests |
| `Parallel` | switch | No | `$false` | Parallel testing (PowerShell 7+) |
| `AdditionalEndpoints` | string[] | No | `@()` | Additional FQDNs to test |

## 🔍 Tested Endpoints

The script automatically tests these critical Microsoft endpoints:

- **manage.microsoft.com** - Microsoft Management Portal
- **enterpriseregistration.windows.net** - Azure AD Registration
- **device.login.microsoftonline.com** - Device Authentication
- **login.microsoftonline.com** - Azure AD Authentication
- **ztd.dds.microsoft.com** - Zero Touch Deployment
- **cs.dds.microsoft.com** - Configuration Services
- **www.msftconnecttest.com** - Microsoft Connectivity Test
- **graph.microsoft.com** - Microsoft Graph API
- **portal.azure.com** - Azure Portal

## 📊 Output Formats

### CSV Report
Standard output with columns:
- **Timestamp**: Test execution time
- **Category**: Test category (Environment, Firewall, Proxy, DNS, TCP, TLS, Summary)
- **Item**: Specific test item
- **SubItem**: Additional test detail
- **Status**: OK, FAIL, WARN, or INFO
- **Data**: Detailed test results

### JSON Report
Optional structured data output for automation and integration.

### Console Summary
Color-coded real-time results with PASS/FAIL/WARN counts.

## 🛠️ Use Cases

### 1. ESP Troubleshooting
When devices stall during enrollment:
```powershell
.\Test-IntuneAutopilotConnectivity.ps1 -AsSystem
```

### 2. Pre-deployment Validation
Before rolling out Autopilot:
```powershell
.\Test-IntuneAutopilotConnectivity.ps1 -OutputPath C:\Reports\PreDeployment.csv
```

### 3. Network Change Validation
After firewall/proxy changes:
```powershell
.\Test-IntuneAutopilotConnectivity.ps1 -Parallel -TimeoutMs 10000
```

### 4. Support Ticket Documentation
Generate evidence for network issues:
```powershell
.\Test-IntuneAutopilotConnectivity.ps1 -OutputPath C:\Support\Ticket123.csv -JsonPath C:\Support\Ticket123.json
```

## 🔧 Troubleshooting

### Common Issues

#### Script Won't Run
- Ensure PowerShell execution policy allows scripts
- Run as Administrator for full functionality
- Check PowerShell version compatibility

#### Network Tests Fail
- Verify firewall allows outbound HTTPS (port 443)
- Check proxy configuration
- Ensure DNS resolution works

#### SYSTEM Task Creation Fails
- Verify administrative privileges
- Check Task Scheduler service is running
- Ensure ProgramData directory is accessible

### Debug Mode
For troubleshooting, examine the detailed CSV output which includes:
- Exact error messages
- Network configuration details
- Certificate information
- Proxy detection results

## 🤝 Contributing

We welcome contributions! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Development Guidelines
- Maintain PowerShell 5.1 compatibility
- Follow PSScriptAnalyzer best practices
- Add comprehensive error handling
- Include parameter validation
- Update documentation for new features

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Microsoft Intune and Autopilot teams
- PowerShell community
- Windows administrators worldwide

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/bijudevops/IntuneNetworkCheck/issues)
- **Discussions**: [GitHub Discussions](https://github.com/bijudevops/IntuneNetworkCheck/discussions)
- **Wiki**: [Repository Wiki](https://github.com/bijudevops/IntuneNetworkCheck/wiki)

## 🔄 Version History

- **v1.0** - Initial release with comprehensive network validation
- Full Intune/Autopilot endpoint coverage
- SYSTEM context support
- Parallel testing capabilities
- SSL inspection detection

---

**Made with ❤️ for the Windows/Intune community**

*Helping engineers deploy and manage Windows devices with confidence.*
