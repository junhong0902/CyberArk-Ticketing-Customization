### Logging
$ErrorActionPreference="SilentlyContinue"
###Stop-Transcript | out-null
###$ErrorActionPreference = "Continue"
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptPath = $scriptPath + "\ticketinglog.txt"
Start-Transcript -path $scriptPath | out-null #Start-Transcript -path $scriptPath -append | out-null

# Base64Encode

function 64encode
{
    Param (
        $inputstg
    )
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($inputstg))
}


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
    
    $APIURL = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[0]))
    $LogonUsername = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[1]))
    $LogonSecret = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[2]))
    $TicketID = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[3]))

    
    $APIURL = magic $APIURL
    $TicketID = magic $TicketID
    $LogonUsername = magic $LogonUsername
    $LogonSecret = magic $LogonSecret
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

$ToCyberArk = @{ 'exists' =  'true'; 'requester' = '' ; 'approver' = ''; 'obj' = ''; 'vts' = ''; 'vte' = ''; 'errormsg' = '' }

switch($strActionName)
{
    'CHG'
    {    
        try
        {
            $logonreturn = (Invoke-WebRequest -Uri "$restURL" -ContentType application/json)

            
            $secrets = (Invoke-RestMethod -Method Get -Uri "$restURL" -ContentType application/json)

            if ($secrets.get_length() -eq 0)
            {
                $ToCyberArk.exists = 64encode 'false'
            }
            else
            {
                $ToCyberArk.exists = 64encode 'true'
                $ToCyberArk.requester = 64encode (magic $secrets.requester)
                $ToCyberArk.approver = 64encode (magic $secrets.approver)
                $ToCyberArk.obj = 64encode (magic $secrets.obj)
                $ToCyberArk.vts = 64encode (magic $secrets.validstart)
                $ToCyberArk.vte = 64encode (magic $secrets.validend)
            }
        }
        catch
        {
            $ToCyberArk.errormsg = 64encode 'Cannot connect to Ticketing System.'
        }


    }
    'INC'
    {
        $restURLget =  $restURL + "?ticketid=eq." + $TicketID.tolower()
        $secrets = (Invoke-RestMethod -Method Get -Uri "$restURLget" -ContentType application/json)
        if ($secrets.get_length() -eq 0)
        {
            $ToCyberArk.exists = 'false'
        }
        else
        {
            $ToCyberArk.exists = 64encode 'true'
            $ToCyberArk.requester = 64encode (magic $secrets.requester)
            $ToCyberArk.obj = 64encode (magic $secrets.obj)
            $ToCyberArk.vts = 64encode (magic $secrets.validstart)
            $ToCyberArk.vte = 64encode (magic $secrets.validend)
        }
    }
}

$ToCyberArk = ConvertTo-Json @($ToCyberArk)
echo $ToCyberArk.Substring(3,$ToCyberArk.Length-5)



<#
# Original code
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
            if (((magic $obj) -eq (magic $secrets.obj)) -and ((magic $TicketID) -eq (magic $secrets.ticketid)) -and ((magic $cArkRequester) -eq (magic $secrets.requester)))
            {
	            echo "VALID"
            }else
            {
	            echo "INVALID"
            }
        }
    }
}
#>





Stop-Transcript | out-null