#$URL $USERNAME $PASSWORD
$URL = $Args[0] 
$Username = $Args[1] 
$CurrentPassword = $Args[2] 

$myUsername = whoami
$myHostname = hostname
Write-Debug $(Get-Date)
Write-Debug "$myUsername is on $myHostname"

Write-Debug "Rapid7 heartbeat for $Username"

#Bypass Certificate checks
Add-Type @"
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
$defaultCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy


if ($URL -notmatch "^(?:https:\/\/)?((?:\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)|\w+(?:.domain.com)?)(?::\d+)$") {
    $URLMatches = $URL -match '^(?:http(?:s)?:\/\/)?((?<IP>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)|(?<SUBDOMAIN>\w+))(?:\.domain\.com)?(?::\d+)?(?:\/(?:.*)?)?$'
    if ($Matches['IP'] -ne $null) {
        $URL = "https://" + $Matches['IP'] + ":3780"
    }
    elseif ($Matches['SUBDOMAIN'] -ne $null) {
        $URL = "https://" + $Matches['SUBDOMAIN'] + ".domain.com:3780"
    }
    else {
        throw "URL Error"
    }
}
$api = $URL
$loginURI = "/api/3"

$credPair = "$($Username):$($CurrentPassword)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$headers = @{ Authorization = "Basic $encodedCredentials" }
#$headers.Add('Content-Type', 'application/json')
$Rapid7Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession #stores the web session including auth cookies

$uri = $api + $loginURI 
try {
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $loginResult = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -SessionVariable $Rapid7Session -ContentType 'application/json' -UseBasicParsing
    #$loginResultContent = $loginResult.Content | ConvertFrom-Json
    #$loginResultContent.links
    [System.Net.ServicePointManager]::CertificatePolicy = $defaultCertPolicy
    Write-Debug "Final Certificate policy is $([System.Net.ServicePointManager]::CertificatePolicy)"
    if ($loginResult.StatusCode -eq 200) {
        Write-Debug "Login Success"
        $AllowAdminTakeover =$True
    }
    else {
        #Write-Debug "UnknownError"
        throw "UnknownError"
    }
}
catch {
    if($_.Exception.Message.ToString().Contains("(401) Unauthorized")) {
        #Write-Debug "Failed"
        throw "Login Failed"
    } else {
        #Write-Debug "UnableToConnect"
        throw "UnableToConnect"
    }
}
