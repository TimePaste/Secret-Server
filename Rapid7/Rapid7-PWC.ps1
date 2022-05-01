#$URL $USERNAME $NEWPASSWORD $PASSWORD $[1]$USERNAME $[1]$PASSWORD
<#
To prevent account takeover, the current password of the user's account must be operational. 
#>



$URL = $Args[0] 
$Username = $Args[1] 
$NewPassword = $Args[2]
$CurrentPassword = $Args[3] 
$AdminUsername = $Args[4]
$AdminPassword = $Args[5]

$myUsername = whoami
$myHostname = hostname
Write-Debug $(Get-Date)
Write-Debug "$myUsername is on $myHostname"

Write-Debug "Rapid7 password change for $Username"

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
$usersURI = "/api/3/users"

$credPair = "$($Username):$($CurrentPassword)"
$encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
$headers = @{ Authorization = "Basic $encodedCredentials" }
#$headers.Add('Content-Type', 'application/json')
$Rapid7Session = New-Object Microsoft.PowerShell.Commands.WebRequestSession #stores the web session including auth cookies

$AllowAdminTakeover = $False
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

if ($AllowAdminTakeover) {
    $TargetUserID = $null
    $credPair = "$($AdminUsername):$($AdminPassword)"
    $encodedCredentials = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credPair))
    $headers = @{ Authorization = "Basic $encodedCredentials" }
    $Rapid7AdministratorSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession #stores the web session including auth cookies

    $uri = $api + $usersURI 
    try {
	    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $userListResult = Invoke-WebRequest -Method GET -Uri $uri -Headers $headers -SessionVariable $Rapid7AdministratorSession -UseBasicParsing
        $userListResultContent = $userListResult.Content | ConvertFrom-Json
        $allUsers = $userListResultContent.resources
        while ($($userListResultContent.links | Where-Object { $_.rel -eq "last" } | Select href -ExpandProperty href) -ne $($userListResultContent.links | Where-Object { $_.rel -eq "self" } | Select href -ExpandProperty href)) {
            $userListResult = Invoke-WebRequest -Method GET -Uri $($userListResultContent.links | Where-Object { $_.rel -eq "next" } | Select href -ExpandProperty href) -Headers $headers -SessionVariable $Rapid7AdministratorSession -UseBasicParsing
            $userListResultContent = $userListResult.Content | ConvertFrom-Json
            $allUsers += $userListResultContent.resources
        }
        $TargetUserID = $allUsers | Where-Object { $_.login -eq "$Username" } | Select id -ExpandProperty id
        [System.Net.ServicePointManager]::CertificatePolicy = $defaultCertPolicy
        Write-Debug "Final Certificate policy is $([System.Net.ServicePointManager]::CertificatePolicy)"
        if ($userListResult.StatusCode -eq 200) {
            Write-Debug "Users retrieved successfully"
        }
        else {
            #Write-Debug "UnknownError"
            throw "UnknownError"
        }
    }
    catch {
        if($_.Exception.Message.ToString().Contains("(401) Unauthorized")) {
            #Write-Debug "Failed"
            throw "Password Change Failed"
        } else {
            #Write-Debug "UnableToConnect"
            throw "Something went wrong"
        }
    }

    if ($TargetUserID -ne $null) {
        $pwURI = "/api/3/users/$TargetUserID/password"
        $uri = $api + $pwURI
        $pwBody = @{
            'password' = $NewPassword
            'passwordResetOnLogin' = $False
        }
        $json = $pwBody  | ConvertTo-Json
        try {
	        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            #back to the original user session where the user can change their own password
            #since according to https://help.rapid7.com/insightvm/en-us/api/index.html#operation/resetPassword
            # "Users may only change their own password."
            $passwordChangeResult = Invoke-WebRequest -Method Put -Uri $uri -Headers $headers -Body $json -SessionVariable $Rapid7Session -UseBasicParsing -ContentType "application/json"
            #$passwordChangeContent = $passwordChangeResult.Content | ConvertFrom-Json
            [System.Net.ServicePointManager]::CertificatePolicy = $defaultCertPolicy
            Write-Debug "Final Certificate policy is $([System.Net.ServicePointManager]::CertificatePolicy)"
            if ($passwordChangeResult.StatusCode -eq 200) {
                Write-Debug "Password Change Success"
            }
            else {
                #Write-Debug "UnknownError"
                throw "UnknownError"
            }
        }
        catch {
            if($_.Exception.Message.ToString().Contains("(401) Unauthorized")) {
                #Write-Debug "Failed"
                throw "Password Change Failed"
            } else {
                #Write-Debug "UnableToConnect"
                throw "UnableToConnect"
            }
        }
    } else {
            #Write-Debug "User Retrieval Failed"
            throw "User Retrieval Failed"
    }
}
