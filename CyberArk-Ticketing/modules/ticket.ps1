$TicketID = $args[0]
### Global Variable Assignment
$ccp_srv = "comp2.jhdomain.com"
$app_id = "Sample"	## Insert Application ID
#$virtual = "cardbapp"	## Insert Virtual Name
#$safe = "Test-DB-MySQL"		## Insert Safe Name 

# Ignore SSL certificate
add-type -TypeDefinition  @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


$secrets = (Invoke-RestMethod -Method Get -Uri "https://$ccp_srv/AIMWebService/api/Accounts?AppID=$app_id&Query=Object=ticketing-dummy" -ContentType application/json)

$ValidTicketID = $secrets.ticketid

if ($TicketID.ToUpper() -eq $ValidTicketID.ToUpper())
{
	echo "VALID"
}else
{
	echo "INVALID"
}
