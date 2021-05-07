### Logging
$ErrorActionPreference="SilentlyContinue"
###Stop-Transcript | out-null
###$ErrorActionPreference = "Continue"
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptPath = $scriptPath + "\ticketinglog.txt"
Start-Transcript -path $scriptPath | out-null #Start-Transcript -path $scriptPath -append | out-null

#Specify prefix (ALWAYS in UPPER!!!)
$CHGprefix = "CHG"
$INCprefix = "INC"
$INCcreate = "CINC"


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
    $cArkRequester = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[4]))
    $obj = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[5]))
    $INCstart = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[6]))
    $INCend = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($args[7]))

    
    $APIURL = magic $APIURL
    $TicketID = magic $TicketID
    $LogonUsername = magic $LogonUsername
    $LogonSecret = magic $LogonSecret
    $cArkRequester = magic $cArkRequester
    $obj = magic $obj
    $INCstart = magic $INCstart
    $INCend = magic $INCend
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

$ToCyberArk = @{ 'exists' =  'false'; 'requester' = '' ; 'approver' = ''; 'obj' = ''; 'vts' = ''; 'vte' = ''; 'errormsg' = '' }

### add https:// if missing in URL
if ($APIURL.Substring(0, [Math]::Min($APIURL.Length, 4)).ToUpper() -ne 'HTTP')
{
	$APIURL = "https://" + $APIURL
}

### Check if it is incident or change request
if ($TicketID.Substring(0, [Math]::Min($TicketID.Length, $CHGprefix.Length)).ToUpper() -eq $CHGprefix)
{
    $strActionName =$CHGprefix

    if ($APIURL.Substring($APIURL.get_Length()-1) -ne '/')
    {
        $restURL = $APIURL + "/change?ticketid=eq." + ($TicketID.substring($CHGprefix.Length)).tolower()
    }
    else
    {
        $restURL = $APIURL + "change?ticketid=eq." + ($TicketID.substring($CHGprefix.Length)).tolower()
    }
	
    #write-host $restURL
}
elseif ($TicketID.Substring(0, [Math]::Min($TicketID.Length, $INCprefix.Length)).ToUpper() -eq $INCprefix)
{
    $strActionName = $INCprefix

    if ($APIURL.Substring($APIURL.get_Length()-1) -ne '/')
    {
        $restURL = $APIURL + "/incident?ticketid=eq." + ($TicketID.substring($INCprefix.Length)).tolower()
    }
    else
    {
        $restURL = $APIURL + "incident?ticketid=eq." + ($TicketID.substring($INCprefix.Length)).tolower()
    }
}
elseif ($TicketID.Substring(0, [Math]::Min($TicketID.Length, $INCCreate.Length)).ToUpper() -eq $INCcreate)
{
    $strActionName = $INCcreate

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
    $ToCyberArk.errormsg = 64encode "Invalid TicketID: $TicketID"
    $ToCyberArk = ConvertTo-Json @($ToCyberArk)
    echo $ToCyberArk.Substring(3,$ToCyberArk.Length-5)
    break
}



switch($strActionName)
{
    $CHGprefix
    {    
        $connection = 0
        try
        {
            (Invoke-WebRequest -Uri "$restURL" -ContentType application/json) | Out-Null
            #write-host $restURL
            $connection = 1
        }
        catch
        {
            $ToCyberArk.errormsg = 64encode 'Cannot connect to Ticketing System.'
        }

        if ($connection)
        {

            $respond = (Invoke-RestMethod -Method Get -Uri "$restURL" -ContentType application/json)
            #write-host $restURL
            if ($respond.get_length() -eq 0)
            {
                $ToCyberArk.exists = 64encode 'false'
            }
            else
            {
                $ToCyberArk.exists = 64encode 'true'
                $ToCyberArk.requester = 64encode (magic $respond.requester)
                $ToCyberArk.approver = 64encode (magic $respond.approver)
                $ToCyberArk.obj = 64encode (magic $respond.obj)
                $ToCyberArk.vts = 64encode (magic $respond.validstart)
                $ToCyberArk.vte = 64encode (magic $respond.validend)
            }
        }
    }
    $INCprefix
    {
        $connection = 0

        try
        {
            Invoke-WebRequest -Uri "$restURL" -ContentType application/json | Out-Null
            $connection = 1
        }
        catch
        {
            $ToCyberArk.errormsg = 64encode 'Cannot connect to Ticketing System.'
        }

        if ($connection)
        {

            $respond = (Invoke-RestMethod -Method Get -Uri "$restURL" -ContentType application/json)

            if ($respond.get_length() -eq 0)
            {
                $ToCyberArk.exists = 64encode 'false'
            }
            else
            {
                $ToCyberArk.exists = 64encode 'true'
                $ToCyberArk.requester = 64encode (magic $respond.requester)
                $ToCyberArk.approver = 64encode (magic $respond.approver)
                $ToCyberArk.obj = 64encode (magic $respond.obj)
                $ToCyberArk.vts = 64encode (magic $respond.validstart)
                $ToCyberArk.vte = 64encode (magic $respond.validend)
            }
        }

    }
    $INCcreate
    {
        $connection = 0
        try
        {
            $logonreturn = (Invoke-WebRequest -Uri "$restURL" -ContentType application/json) | Out-Null
            $connection = 1
        }
        catch
        {
            $ToCyberArk.errormsg = 64encode 'Cannot connect to Ticketing System.'
        }

        if ($connection)
        {
            $json = @{'validstart' =  $INCstart; 'validend' =  $INCend;'requester' = (magic $cArkRequester); 'approver' = 'INCcreate'; 'obj' = (magic $obj)}
            
            try
            {
                Invoke-RestMethod -Method Post -Uri "$restURL" -Body $json
            }
            catch
            {
                $ToCyberArk.errormsg = 64encode 'Fail to create ticket.'
            }

            $restURL = $restURL + "?requester=eq." + $cArkRequester + "&validstart=eq." + $INCstart
            $respond = (Invoke-RestMethod -Method Get -Uri "$restURL" -ContentType application/json)

            if ($respond.get_length() -eq 0)
            {
                $ToCyberArk.errormsg = 64encode "Error during Ticket creation."
            }
            else
            {
                $TicketIDcreated = $INCprefix + $respond.ticketid
                $ToCyberArk.errormsg = 64encode "Ticket created. TicketID is $TicketIDcreated"
                $ToCyberArk.exists = 64encode 'true'
                $ToCyberArk.requester = 64encode (magic $respond.requester)
                $ToCyberArk.approver = 64encode (magic $respond.approver)
                $ToCyberArk.obj = 64encode (magic $respond.obj)
                $ToCyberArk.vts = 64encode (magic $respond.validstart)
                $ToCyberArk.vte = 64encode (magic $respond.validend)
            }
        }

    }
}

$ToCyberArk = ConvertTo-Json @($ToCyberArk)
echo $ToCyberArk.Substring(3,$ToCyberArk.Length-5)


Stop-Transcript | out-null