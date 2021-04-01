# CyberArk-TicketingPlugin
 
Main code: Main.cs
### To Do if want to recreate dll

In visual studio install Newtonsoft.Json to parse Json (Project -> manage nuget)

### Functions implemented:
1. APP hash validation (Using AIM hashing method, use 'NULL' to bypass)
2. BYPASS ticketID for emergency access
3. Simple ticketID validation (dll or powershell -> ccp -> Get dummy account's ticketID parameter and compare)
4. Perform Restapi call directly from dll
5. Invoke a Powershell script and get output
6. INC and CHG ticketing system with PostGres database (By powershell)

### Read debug log
```
Get-Content C:\Windows\Temp\PVWA\PVWA.App.log -wait | Select-String -Pattern "TicketID"
```
