# CyberArk-TicketingPlugin
```
Project file: CyberArk-Ticketing.sln 
Main code: CyberArk-Ticketing/Main.cs
PS script location: CyberArk-Ticketing/modules/ticket.ps1
Simulated Ticketing System (For credentials please check AMI's description): 
  For NSSG user: Create a EC2 instance with private AMI "CyberArk Ticketing AMI"
  Ticketing API URL: http://<public ip of EC2 instance>
                     ex: http://<public ip of EC2 instance>/change?ticketid=eq.chg001 (Query ticket in "change" database with ticketID equals to chg001)
  To access ticketing database: http://<public ip of EC2 instance>:8080
```

### To Do if want to recreate dll

In visual studio install Newtonsoft.Json to parse Json (Project -> manage nuget)

### Functions implemented:
1. APP hash validation (Using AIM hashing method, use 'NULL' to bypass)
2. BYPASS ticketID for emergency access
3. Perform Restapi call directly from dll
4. Invoke a Powershell script and get output
5. INC and CHG ticketing system with PostGres database (By powershell)

### Read debug log
```
Get-Content C:\Windows\Temp\PVWA\PVWA.App.log -wait | Select-String -Pattern "TicketID"
```

### Powershell log
If enable logging in powershell script, powershell's log can be found under same directory of powershell script.

### Postgres limitation
Do note that postgres is case-sensetive, becareful with data entry.

### PVWA Parameters (CASE-SENSITIVE!)
	1. APIHash - 'NULL' or HASHVALUE - Mandatory
	2. HashApp - 'AIMGetAppInfo.exe' - Mandatory if APIHASH != NULL, the hash AIM hash app's name
	3. ModuleDirectory - 'C:\TicketingModules' - Mandatory, permission rrw to 'IIS APPPOOL\PasswordVaultWebAccessPool'
	4. BypassID - 'BYPASSTICKET' - Optional
	5. APIURL - 'https://www.jhdomain.com:3000' - Mandatory
	6. INCduration - '48' - Optional - Default 24 hours, in terms of hours
	7. CheckApprover - 'true' - Optional - Default true - Check if Approver != Requester
	8. CheckRequester - 'false' - Optional - Default true - Check if Requester == Requester
	9. CheckTime - 'true' - Optional - Default true - Validate current time within vts vte
	10. CheckObj - 'false' - Optional - Default true - Validate requested obj!

