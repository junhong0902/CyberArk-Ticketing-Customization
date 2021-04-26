# CyberArk-TicketingPlugin
```
Project file: CyberArk-Ticketing.sln 
Main code: CyberArk-Ticketing/Main.cs
PS script location: CyberArk-Ticketing/modules/ticket.ps1
Simulated Ticketing System: 
  For NSSG user: Create a EC2 instance with private AMI "CyberArk Ticketing AMI"
  Ticekting API URL: http://<public ip of EC2 instance>
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
