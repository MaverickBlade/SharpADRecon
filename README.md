![](https://img.shields.io/badge/C%23-.NET%204.8-512BD4?style=for-the-badge&labelColor=2D2D2D&logo=csharp)![](https://img.shields.io/badge/Size-671%20KB-00C853?style=for-the-badge&labelColor=2D2D2D)![](https://img.shields.io/badge/Modules-29-FF6D00?style=for-the-badge&labelColor=2D2D2D)![](https://img.shields.io/badge/Dependencies-Zero-E91E63?style=for-the-badge&labelColor=2D2D2D)![](https://img.shields.io/badge/Report-HTML_+_Excel-FF6D00?style=for-the-badge&labelColor=2D2D2D)

# ⚡ ADRecon.NET

**🔥 One EXE. Zero Dependencies. Full AD Recon. 🔥**  

*A native C# port of [ADRecon v1.27](https://github.com/adrecon/ADRecon) — compiled into a **single self-contained executable** with everything embedded.*  
*Download. Drop. Run. No PowerShell. No RSAT. No NuGet. Just LDAP.*

![](https://img.shields.io/badge/🚀_Quick_Start-Click_Here-2196F3?style=for-the-badge) ![](https://img.shields.io/badge/📥_Download-Release-4CAF50?style=for-the-badge) 

---

> ⚠️ **Disclaimer:** This tool is provided for **authorized security testing and educational purposes only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before performing security assessments.



## 🔥 Why ADRecon.NET?



### ❌ ADRecon (Original)

- 🐚 PowerShell 5.1 required
- 📦 RSAT / ActiveDirectory module
- 🐌 Slow module imports
- 😓 execute-assembly bypass needed
- 📊 Excel only
- 👀 Console window visible



### ✅ [ADRecon.NET](http://ADRecon.NET)

- ⚡ **Pure C# — no PowerShell**
- 🎯 **Single EXE — zero deps**
- 🚀 **Instant — no module loading**
- 💎 **Native execute-assembly**
- 📊 **Excel + Interactive HTML**
- 🔒 **Pure LDAP traffic**

---



## 🎯 Quick Start

```powershell
AdRecon.exe -Credential "DOMAIN\user:password"
```

> 💡 **That's it.** Produces CSV + Excel + HTML report in a timestamped folder.

---



## 🌟 Features



### 📦 29 Collection Modules


|                           |                                    |
| ------------------------- | ---------------------------------- |
| 🌐 **Forest**             | Forest metadata, functional levels |
| 🏢 **Domain**             | Domain info, roles, SID            |
| 🔗 **Trusts**             | Trust direction, type              |
| 📍 **Sites/Subnets**      | AD topology                        |
| 📜 **SchemaHistory**      | Schema changes                     |
| 🔐 **PasswordPolicy**     | Default policy + compliance        |
| 🎯 **FineGrainedPPS**     | PSO settings                       |
| 🖥️ **DomainControllers** | DCs, FSMO, SMB probe               |
| 👤 **Users**              | **55 attributes** per user         |
| 🔑 **UserSPNs**           | Service principal names            |
| 📋 **PasswordAttributes** | Age, expiry, flags                 |
| 👥 **Groups**             | Membership, type, history          |
| 🏗️ **OUs**               | Organizational units               |
| 📑 **GPOs/GPLinks**       | Group policy links                 |
| 📊 **GPOReport**          | Full GPO audit                     |
| 🌐 **DNS**                | Zones + records                    |
| 🖨️ **Printers**          | Printer queues                     |
| 💻 **Computers**          | Computer objects                   |
| 🔐 **LAPS**               | LAPS password state                |
| 🔑 **BitLocker**          | Recovery keys                      |
| 🛡️ **ACLs**              | DACL + SACL                        |
| 🍯 **Kerberoast**         | TGS extraction                     |
| 📡 **ServiceLogon**       | Domain service accounts            |




### 🔒 Security Features


| Feature                 | Description                                      |
| ----------------------- | ------------------------------------------------ |
| 📦 **Single EXE**       | No child processes, no DLL side-loading          |
| 🌐 **Pure LDAP**        | No PowerShell, no WMI, no SMB (except DC probes) |
| 💾 **Embedded Libs**    | jQuery, Chart.js, DataTables inside the EXE      |
| 🎯 **execute-assembly** | Native support — just run it                     |


---



## 📥 Download

> **[Download Latest Release]**

**Requirements:**

- 🪟 Windows with .NET Framework 4.0+ (4.8 recommended)
- 🌐 LDAP access to a domain controller (port 389)
- 🔑 Domain account with read access

---



## 📖 Usage

```
AdRecon.exe [options]
```



### 🔌 Connection


| Flag                                | Description                                      | Default         |
| ----------------------------------- | ------------------------------------------------ | --------------- |
| 🌐 `-Domain <fqdn>`                 | Target domain                                    | Current domain  |
| 🖥️ `-DomainController <dc>`        | DC to bind to (alias: `-DC`)                     | Auto-detect     |
| 🔑 `-Credential <user:pass>`        | `DOMAIN\user:password` or `user@domain:password` | Current context |
| 👤 `-Username <user>` + `-Password` | Split credential (password prompted if omitted)  | —               |




### 📦 Collection


| Flag                 | Description                                   | Default              |
| -------------------- | --------------------------------------------- | -------------------- |
| 📋 `-Collect <list>` | Modules: comma-separated, `Default`, or `All` | Default (26 modules) |
| ✅ `-OnlyEnabled`     | Only report enabled accounts                  | Off                  |




### 📊 Output


| Flag                         | Description                                            | Default            |
| ---------------------------- | ------------------------------------------------------ | ------------------ |
| 📄 `-OutputType <list>`      | `CSV`, `XML`, `JSON`, `HTML`, `Excel`, `STDOUT`, `All` | `CSV,Excel`        |
| 📁 `-OutputDir <path>`       | Result folder                                          | Timestamped in cwd |
| 📊 `-GenExcel <dir>`         | Regenerate Excel from existing CSV-Files               | —                  |
| 🌐 `-GenReport <true/false>` | Generate HTML report                                   | `true`             |
| 🏷️ `-Logo <text>`           | Heading text in reports                                | `ADRecon`          |




### ⚙️ Tuning


| Flag                         | Description                   | Default |
| ---------------------------- | ----------------------------- | ------- |
| 🔐 `-PassMaxAge <days>`      | Password age threshold        | 30      |
| 🕐 `-DormantTimeSpan <days>` | Last-logon threshold          | 90      |
| 📄 `-PageSize <n>`           | LDAP page size                | 200     |
| 📝 `-Log`                    | Write ADRecon-Console-Log.txt | Off     |


---



## 💡 Examples

```powershell
# 🔐 Default recon with explicit credentials
AdRecon.exe -Credential "CORP\svc.recon:Password123"

# ⚡ Quick user + computer dump to console
AdRecon.exe -Collect Users,Computers -OutputType STDOUT

# 🚀 Full recon with all output formats
AdRecon.exe -Collect All -OutputType CSV,XML,JSON,HTML -OutputDir C:\recon\out

# 📊 Regenerate Excel from existing CSV output
AdRecon.exe -GenExcel "C:\recon\ADRecon-20260911"

# 🎯 Target specific DC with custom thresholds
AdRecon.exe -DC dc01.corp.local -Credential "CORP\admin:P@ss" -PassMaxAge 60 -DormantTimeSpan 30
```

---



## 🏆 Module Highlights

**👤 Users — 55-Column Attribute Dump**

`DisplayName` `SAMAccountName` `Enabled` `SID` `DN` `UPN` `Title` `Department` `Company` `Email` `Phone` `Address` `Manager` `AdminCount` `DonNotExpire` `DonNotReqPreAuth` `LockoutTime` `LogonCount` `LastLogon` `PasswordAge` `PasswordLastSet` `PasswordNeverExpires` `CannotChangePassword` `MustChangePassword` `ReversibleEncryption` `SmartcardRequired` `DelegationPermitted` `DelegationType` `KerberosDES` `KerberosRC4` `KerberosAES128` `KerberosAES256` `SIDHistory` `SIDHistoryCount` `Dormant` `LastLogonTimestamp` `Description` `Comment` `Created` `Modified`

**🍯 Kerberoast — TGS Extraction for Offline Cracking**

Requests a TGS ticket per user SPN via `KerberosRequestorSecurityToken` (System.IdentityModel) and extracts the embedded ticket ciphertext into John the Ripper / Hashcat format lines. Works with or without `-Credential`.

**🛡️ ACLs — DACL + SACL Enumeration**

Full security descriptor enumeration with GUID-to-readable-name resolution for all object types. Includes both DACL (permissions) and SACL (auditing) entries.

**🖥️ DomainControllers — SMB Dialect Probe**

Enumerates DCs, FSMO roles, and performs SMB dialect negotiation on port 445 to detect SMBv1/v2/v3 support and signing status.

---



## 📊 Stats


|                                                                                            |                                                                                                 |                                                                                     |                                                                                              |                                                                                                          |
| ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| ![](https://img.shields.io/badge/Modules-29-FF6D00?style=for-the-badge) Collection Modules | ![](https://img.shields.io/badge/User_Attributes-55-2196F3?style=for-the-badge) Per User Object | ![](https://img.shields.io/badge/Size-671_KB-4CAF50?style=for-the-badge) Single EXE | ![](https://img.shields.io/badge/Dependencies-Zero-E91E63?style=for-the-badge) Zero Required | ![](https://img.shields.io/badge/Compliance-4_Standards-9C27B0?style=for-the-badge) PCI DSS / ACSC / CIS |


---



## 🙏 Credits

**ADRecon** was created by [Prashant Mahajan (@prashant3535)](https://github.com/prashant3535) at [Sense of Security](https://senseofsecurity.com.au).

Source: [github.com/adrecon/ADRecon](https://github.com/adrecon/ADRecon) — **GNU AGPL v3**

This .NET port extends the original with:

- 🌐 Interactive HTML dashboard
- 📦 Embedded libraries (jQuery, Chart.js, DataTables)
- 📊 GPOReport module (LDAP-based, no RSAT)
- 💎 Single EXE — zero dependencies

---



## 📜 License

GNU Affero General Public License v3.0 — see [LICENSE.md](../ADRecon-master/LICENSE.md)

---

