<#
.SYNOPSIS
Mitigation of WannaCrypto Ransomware techniques.

.DESCRIPTION
Mitigation of WannaCrypto Ransomware techniques. Will determine proper operating system on each computer/server and take appropriate actions.

.NOTES
Written by JBear
Date: 5/14/2017

Function Crypto-Fix-W10-2012 will fail if PowerShell is out of date or cmdlets are unavailable on the remote machine. Test cmdlets individually if you run into an issue.
#>

Param(

    #To set default value, change mandatory to ValueFromPipeline and make $ComputerName = whatever command to pull a list
    [Parameter(Mandatory=$true)]
    [String[]]$ComputerName
)

function Crypto-Fix-W7-2008 {

#Add desired registry key values to array
$Keys = @(

    "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters"       
)

    Invoke-Command -ComputerName $Computer {
    param($Computername, $Computer, $Keys)
        
        foreach ($Key in $Keys) {        

            Try {
                        
                #Change value of -Name
                New-ItemProperty -Path $Key -Name "SMB1" -Value "0" -PropertyType DWORD -Force | Out-Null
                Write-Output -ForegroundColor Green "Successful key injection on $Computer."
            }

            Catch {
    
                Write-Output "Notice: Unable to add key to $Computer."
            }
        }
    } -AsJob -JobName "Crypto Fix (RansomWare Mitigation)" -ArgumentList $Computername, $Computer, $Keys    
}#End Crypto-Fix-W7-2008

function Crypto-Fix-W10-2012 {

    Invoke-Command -ComputerName $Computer {
    param($Computername, $Computer, $Keys)
        
        #Disable SMB1 protocol
        Set-SmbServerConfiguration -EnableSMB1Protocol $false
    } -AsJob -JobName "Crypto Fix (RansomWare Mitigation)" -ArgumentList $Computername, $Computer, $Keys        
}#End Crypto-Fix-W10-2012

foreach ($Computer in $ComputerName) {
    
    if(!([String]::IsNullOrWhiteSpace($Computer))) {

        if(Test-Connection -Quiet -Count 1 -Computer $Computer) {

            Try {

                $WMI = (Get-WmiObject -ClassName WIN32_OperatingSystem -Computer $Computer).Caption
            }

            #Break from outside loop
            Catch {
                
                Write-Host -ForegroundColor Yellow "Notice: Unable to retrieve Operating System information for $Computer."
                Break
            }
            
            #If Windows 7 or Server 2008
            if($WMI -like "*Windows 7*" -or $WMI -like "*Server 2008*") {
            
                #Call Windows 7/Server 2008 function
                Crypto-Fix-W7-2008
            }

            #If Windows 8/10 or Server 2012/2016
            elseif($WMI -like "*Windows 10*" -or $WMI -like "*Windows 8*" -or $WMI -like "*Server 2012*" -or $WMI -like "*Server 2016*") {
            
                #Call Windows 10/Server 2012/Server 2016 function
                Crypto-Fix-W10-2012
            }

            #No Operating System matches
            else {
            
                Write-Host -ForegroundColor Red "No operating system match on $Computer."
            }
        }

        #If ping fails
        else {
        
            Write-Host -ForegroundColor Yellow "Unable to ping $Computer"
        }
    }

    #Values are null
    else {
    
        Write-Host "Value is NULL."
    }
}
