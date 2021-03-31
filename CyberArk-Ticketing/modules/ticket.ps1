### Logging
$ErrorActionPreference="SilentlyContinue"
###Stop-Transcript | out-null
###$ErrorActionPreference = "Continue"
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptPath = $scriptPath + "\ticketinglog.txt"
Start-Transcript -path $scriptPath | out-null #Start-Transcript -path $scriptPath -append | out-null

# Trim and Clean string
function magic
{
    # Function params
    Param (
        $inputstg
    )

    $inputstg = $inputstg.ToLower()
    return ($inputstg.Trim())
    
}

# Trim & convert input from base64 to UTF8
try
{
    $TicketID = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[0]))
    $APIURL = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[1]))
    $cArkRequester = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[2]))
    $obj = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[3]))

    $TicketID = magic $TicketID
    $APIURL = magic $APIURL
    $cArkRequester = magic $cArkRequester
    $obj = magic $obj
}
catch
{
    write-host "Mandatory parameter is missing.\n"
}

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



### add https:// if missing in URL
if ($APIURL.Substring(0, [Math]::Min($APIURL.Length, 3)).ToUpper() -ne 'HTT')
{
	$APIURL = "https://" + $APIURL
}


### Check if it is incident or change request
if ($TicketID.Substring(0, [Math]::Min($TicketID.Length, 3)).ToUpper() -eq 'CHG')
{
    $strActionName = "CHG"

    if ($APIURL.Substring($APIURL.get_Length()-1) -ne '/')
    {
        $restURL = $APIURL + "/change?ticketid=eq." + $TicketID.tolower()
    }
    else
    {
        $restURL = $APIURL + "change?ticketid=eq." + $TicketID.tolower()
    }
	
    #write-host $restURL
}
elseif ($TicketID.Substring(0, [Math]::Min($TicketID.Length, 3)).ToUpper() -eq 'INC')
{
    $strActionName = "INC"

    if ($APIURL.Substring($APIURL.get_Length()-1) -ne '/')
    {
        $restURL = $APIURL + "/incident"
    }
    else
    {
        $restURL = $APIURL + "incident" 
    }
}else
{
    echo "INVALID"
}



### incident or change request
switch($strActionName)
{
    'CHG'
    {    
        $secrets = (Invoke-RestMethod -Method Get -Uri "$restURL" -ContentType application/json)
        if (((magic $obj) -eq (magic $secrets.obj)) -and ((magic $secrets.approver) -ne (magic $cArkRequester)) -and ((magic $TicketID) -eq (magic $secrets.ticketid)) -and ((magic $cArkRequester) -eq (magic $secrets.requester)))
        {
	        echo "VALID"
        }else
        {
	        echo "INVALID"
        }
    }
    'INC'
    {
        $restURLget =  $restURL + "?ticketid=eq." + $TicketID.tolower()
        $secrets = (Invoke-RestMethod -Method Get -Uri "$restURLget" -ContentType application/json)
        if ($secrets.get_length() -eq 0)
        {
            $json = @{'ticketid' =  (magic $ticketID);'requester' = (magic $cArkRequester);'obj' = (magic $obj)}
            
            Invoke-RestMethod -Method Post -Uri "$restURL" -Body $json | out-null
            $secrets = (Invoke-RestMethod -Method Get -Uri "$restURLget" -ContentType application/json)
            if (((magic $obj) -eq (magic $secrets.obj))  -and ((magic $TicketID) -eq (magic $secrets.ticketid)) -and ((magic $cArkRequester) -eq (magic $secrets.requester)))
            {
	            echo "VALID"
            }else
            {
	            echo "INVALID"
            }
        }
        else
        {
            if (((magic $obj) -eq (magic $secrets.obj))  -and ((magic $TicketID) -eq (magic $secrets.ticketid)) -and ((magic $cArkRequester) -eq (magic $secrets.requester)))
            {
	            echo "VALID"
            }else
            {
	            echo "INVALID"
            }
        }
    }
}






Stop-Transcript | out-null