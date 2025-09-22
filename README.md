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

This complete setup provides you with a fully functional Windows Server infrastructure including domain controller, DNS, DHCP, certificate services, and federation services, all configured through PowerShell commands on Server Core.[13][14][7][9][11][8]

[1](https://www.youtube.com/watch?v=CnNKX-yhvbI)
[2](https://www.prajwaldesai.com/sconfig-options-on-windows-server-core/)
[3](https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-sconfig)
[4](https://rdr-it.com/en/windows-server-configure-an-ip-address-on-a-network-card/)
[5](https://woshub.com/configure-windows-server-core-basic-commands/)
[6](https://www.web3us.com/how-guides/administer-server-core-server)
[7](https://woshub.com/windows-server-core-install-active-directory-domain-controller/)
[8](https://www.kjctech.net/setting-up-active-directory-dns-and-dhcp-on-server-core-using-powershell/)
[9](https://mikefrobbins.com/2018/12/06/use-powershell-to-install-a-dhcp-server-on-a-windows-server-2019-server-core-active-directory-domain-controller/)
[10](https://www.c-sharpcorner.com/article/dhcp-role-on-windows-2019-core/)
[11](https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/install-the-certification-authority)
[12](https://itomation.ca/how-to-install-microsoft-ca-on-server-core/)
[13](https://techblog.ptschumi.ch/windows-server/adfs/install-ad-fs-farm-on-windows-server-2019-server-core-with-powershell/)
[14](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/install-the-ad-fs-role-service)
[15](https://campus.barracuda.com/product/websecuritygateway/doc/168723050/how-to-install-ad-cs-on-windows-server/)
[16](https://techbits.io/add-windows-server-core-existing-active-directory-domain/)
[17](https://petri.com/add-domain-controller-to-existing-domain-powershell/)
[18](https://www.youtube.com/watch?v=jQqFxeyquoA)
[19](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/install-active-directory-domain-services--level-100-)
[20](https://help.druva.com/en/articles/8806716-how-to-install-active-directory-certificate-services-on-windows-2012)
[21](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/quickstart-install-configure-dhcp-server)
[22](https://mattglass-it.com/install-active-directory/)
[23](https://www.youtube.com/watch?v=7T7gPHd6afQ)
[24](https://gist.github.com/df052a35eeed5edec256)
[25](https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-administer)
[26](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview)
[27](https://www.youtube.com/watch?v=Woa_dKcu_Vk)
[28](https://www.youtube.com/watch?v=fvOMUzRqtOg)
[29](https://www.youtube.com/watch?v=ntdtjyPkpbI)
[30](https://learn.microsoft.com/en-us/windows-server/networking/dns/quickstart-install-configure-dns-server)
[31](https://gal.vin/domain-controller-windows-server-core-walkthrough/)
[32](https://arnaudpain.com/2019/08/05/windows-server-2019-adfs-step-by-step/)
[33](https://petri.com/windows-server-2022-as-a-domain-controller/)
[34](https://www.redhat.com/en/blog/active-directory-sso-authentication)
[35](https://www.youtube.com/watch?v=5pCb7Sq2HTQ)
[36](https://www.youtube.com/watch?v=joIubWzQ6P8)
[37](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/on-premises-key-trust-adfs)
[38](https://www.linkedin.com/pulse/active-directory-dns-dhcp-configuration-windows-server-kawushika-v0k4c)
[39](https://cloudinfrastructureservices.co.uk/how-to-install-adfs-on-windows-server-2022/)
[40](https://infrasos.com/how-to-setup-active-directory-on-windows-server-2022/)
[41](https://utho.com/docs/windows/how-to-set-static-ip-address-in-windows-server-via-powershell/)
[42](https://mcsa15.biz/mcsa15/configure%20server%20core.pdf)
[43](https://devblogs.microsoft.com/scripting/use-powershell-to-configure-static-ip-and-dns-settings/)
[44](https://www.pdq.com/blog/how-to-use-powershell-to-set-static-and-dhcp-ip-addresses/)
[45](https://www.youtube.com/watch?v=k3domuFyqSI)
[46](https://selmanhaxhijaha.wordpress.com/2014/10/19/configuring-windows-server-core-using-powershell/)
[47](https://www.linkedin.com/pulse/windows-server-core-sconfigexe-santosh-singh)
[48](https://www.readandexecute.com/how-to/server-2016/installing-and-configuring/configure-windows-server-2016-using-sconfig/)
[49](https://stackoverflow.com/questions/68749788/assign-a-static-ip-address-using-powershell)
[50](https://learn.microsoft.com/en-us/windows-server/administration/server-core/server-core-servicing)
[51](https://masteringvmware.com/how-to-configure-networking-in-windows-server-core/)
[52](https://serveracademy.com/courses/installing-and-configuring-windows-server/configure-windows-server-core/)
