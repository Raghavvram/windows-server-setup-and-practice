# Windows Server Core Complete Setup Guide: AD, DC, AD CS, AD FS, DHCP, DNS

This comprehensive guide will walk you through setting up a complete Windows Server infrastructure on Server Core (no GUI) using PowerShell commands. We'll configure Active Directory Domain Services, Certificate Services, Federation Services, DHCP, and DNS step by step.

## Initial Server Setup

### Step 1: Set Administrator Password
When you first boot your Windows Server Core installation, you'll be prompted to set the administrator password.[1]

1. **Enter a strong password** when prompted during first boot
2. **Confirm the password** 
3. Press **Enter** to complete

### Step 2: Launch Server Configuration Tool
Once logged in, the `sconfig` tool should launch automatically. If not:

```powershell
sconfig
```

This opens the Server Configuration menu with 15 numbered options.[2][3]

### Step 3: Configure Basic Settings Using SConfig

**Set Computer Name (Option 2):**
1. Type `2` and press Enter
2. Enter your desired server name (e.g., `DC01`)
3. Type `Y` to restart when prompted[2]

**Configure Network Settings (Option 8):**
1. Type `8` and press Enter
2. Select your network adapter (usually option 1)
3. Choose option 1 to set network configuration
4. Type `S` for Static IP configuration
5. Enter your IP address (e.g., `192.168.1.10`)
6. Enter subnet mask (e.g., `255.255.255.0`) 
7. Enter default gateway (e.g., `192.168.1.1`)
8. Choose option 2 to set DNS servers
9. Enter DNS server IP (initially use external DNS like `8.8.8.8`)[4][5]

### Step 4: Alternative PowerShell Network Configuration
If you prefer PowerShell commands for network setup:

```powershell
# Check current network configuration
Get-NetIPConfiguration

# Set static IP address
New-NetIPAddress -InterfaceIndex 4 -IPAddress 192.168.1.10 -PrefixLength 24 -DefaultGateway 192.168.1.1

# Set DNS servers  
Set-DNSClientServerAddress -InterfaceIndex 4 -ServerAddresses 8.8.8.8,8.8.4.4

# Verify configuration
Get-NetIPConfiguration
```

Replace `4` with your actual interface index from the first command.[5][6]

## Active Directory Domain Services (AD DS) Setup

### Step 1: Install AD DS Role
Open PowerShell and install the Active Directory Domain Services role:

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
```

This command installs AD DS without requiring a reboot.[7][8]

### Step 2: Create New Forest and Domain
Create your first domain controller with a new Active Directory forest:

```powershell
Install-ADDSForest -DomainName "company.local" -DomainNetbiosName "COMPANY" -ForestMode "Win2016" -DomainMode "Win2016"
```

You'll be prompted to:
1. **Enter Safe Mode Administrator Password** - This is for Directory Services Restore Mode
2. **Confirm the password**
3. **Type 'Y'** to proceed with installation and automatic reboot[8][7]

The server will automatically restart after installation. DNS will be installed and configured automatically during this process.[8]

### Step 3: Verify AD Installation
After reboot, verify your domain controller:

```powershell
# Check domain controller status
dcdiag

# Verify AD services are running
Get-Service -Name "ADWS","DNS","KDC","NTDS"

# Check domain and forest functional levels
Get-ADDomain | Select-Object Name, DomainMode
Get-ADForest | Select-Object Name, ForestMode
```

### Step 4: Update DNS Configuration
Now update your server's DNS to point to itself:

```powershell
Set-DNSClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 192.168.1.10
```

Replace `192.168.1.10` with your server's actual IP address.[8]

## DNS Configuration

DNS is automatically installed with AD DS, but you may want to add reverse lookup zones:

```powershell
# Add reverse lookup zone
Add-DnsServerPrimaryZone -ReplicationScope Forest -NetworkId "192.168.1.0/24" -DynamicUpdate Secure

# Verify DNS zones
Get-DnsServerZone
```

## DHCP Server Setup

### Step 1: Install DHCP Role
```powershell
Install-WindowsFeature DHCP -IncludeManagementTools
```

### Step 2: Create DHCP Security Groups
```powershell
netsh DHCP add securitygroups
Restart-Service dhcpserver
```

### Step 3: Authorize DHCP Server in Active Directory
```powershell
Add-DhcpServerInDC -DnsName "DC01.company.local" -IPAddress 192.168.1.10
```

Replace with your actual server name and IP address.[9][10]

### Step 4: Create DHCP Scope
```powershell
# Create DHCP scope
Add-DhcpServerv4Scope -Name "Internal Network" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0 -State Active

# Set exclusion range (for servers)
Add-DhcpServerv4ExclusionRange -ScopeID 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.99

# Configure scope options
Set-DhcpServerv4OptionValue -ScopeID 192.168.1.0 -DNSServer 192.168.1.10 -DNSDomain company.local -Router 192.168.1.1
```

### Step 5: Verify DHCP Configuration
```powershell
# Check DHCP authorization
Get-DHcpServerInDc

# View DHCP scope details
Get-DhcpServerv4Scope | Select-Object -Property *
```

## Active Directory Certificate Services (AD CS) Setup

### Step 1: Install AD CS Role
```powershell
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
```

### Step 2: Configure Enterprise Root CA
```powershell
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 20
```

When prompted, type **A** and press Enter to confirm the installation.[11][12]

### Step 3: Verify CA Installation
```powershell
# Check certificate authority status
Get-CertificationAuthority

# View CA certificates
Get-ChildItem -Path Cert:\LocalMachine\My
```

## Active Directory Federation Services (AD FS) Setup

**Note:** AD FS requires an SSL certificate. For production environments, obtain a proper certificate. For lab environments, you can create a self-signed certificate.

### Step 1: Install AD FS Role
```powershell
Install-WindowsFeature ADFS-Federation -IncludeManagementTools
```

### Step 2: Create SSL Certificate (Lab Environment Only)
For lab environments, create a self-signed certificate:

```powershell
New-SelfSignedCertificate -CertstorelLocation Cert:\LocalMachine\My -DnsName "adfs.company.local" -FriendlyName "ADFS SSL Certificate"

# Get the certificate thumbprint
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*adfs*"}
```

### Step 3: Configure AD FS Farm
Create a service account credential first:

```powershell
$ADFSCred = Get-Credential "COMPANY\Administrator"
```

Then install the AD FS farm (replace the thumbprint with your actual certificate thumbprint):

```powershell
Install-AdfsFarm -CertificateThumbprint "YOURCERTIFICATETHUMBPRINTHERE" -FederationServiceDisplayName "Company ADFS" -FederationServiceName "adfs.company.local" -ServiceAccountCredential $ADFSCred
```

### Step 4: Enable Sign-On Page
```powershell
Set-AdfsProperties -EnableIdPInitiatedSignonPage $true
```

### Step 5: Verify AD FS Installation
```powershell
# Check AD FS service status
Get-Service -Name "adfssrv"

# Test AD FS configuration
Get-AdfsProperties | Select-Object DisplayName, HostName
```

## Final Verification and Testing

### Step 1: Verify All Services
```powershell
# Check all critical services
Get-Service -Name "ADWS","DNS","KDC","NTDS","DHCPServer","adfssrv","CertSvc" | Format-Table Name, Status
```

### Step 2: Test Domain Controller
```powershell
# Run comprehensive DC diagnostics
dcdiag /v

# Test DNS resolution
nslookup company.local

# Test DHCP
Get-DhcpServerv4Lease -ScopeId 192.168.1.0
```

### Step 3: Create Test User Account
```powershell
# Create a test user
New-ADUser -Name "TestUser" -AccountPassword (Read-Host -AsSecureString "Enter Password") -Enabled $true -PasswordNeverExpires $true

# Add user to Domain Admins (for testing)
Add-ADGroupMember -Identity "Domain Admins" -Members "TestUser"
```

## Important Security Considerations

1. **Change default passwords** for all service accounts
2. **Configure Windows Firewall** rules as needed
3. **Enable Windows Updates** using sconfig option 5
4. **Backup your domain controller** regularly
5. **Use proper SSL certificates** in production environments
6. **Implement proper DNS security** measures
7. **Configure time synchronization** with reliable time sources

## Troubleshooting Common Issues

**DNS Issues:**
- Ensure your server points to itself for DNS
- Verify reverse lookup zones are created
- Check firewall rules for DNS traffic

**DHCP Authorization Issues:**
```powershell
# Re-authorize DHCP if needed
Add-DhcpServerInDC -DnsName "DC01.company.local" -IPAddress 192.168.1.10
```

**Certificate Issues:**
- Verify certificate store permissions
- Check certificate validity periods
- Ensure proper certificate templates are available

**AD FS Issues:**
- Verify SSL certificate is properly bound
- Check service account permissions
- Validate DNS resolution for federation service name
