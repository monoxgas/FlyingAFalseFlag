Function Hunt-Azure {
	 <#
	.SYNOPSIS
	Hunt for useful cloud IP addresses in Azure

	Author: Nick Landers (@monoxgas)
	License: BSD 3-Clause
	Required Dependencies: Azure Cmdlets
	Optional Dependencies: None

	.DESCRIPTION
	Hunt for useful cloud IP addresses in Azure

	.EXAMPLE
	C:\PS> Hunt-Azure -ResourceGroup MyGroup

	.PARAMETER ResourceGroup
	Resource group name in Azure

	.PARAMETER RegionFilter
	Wildcard filter for the full region names to hunt in

	.PARAMETER MaxCount
	Maximum addresses to cycle through
	#>

	[CmdletBinding()]
	Param(
	  [Parameter(Mandatory=$True, Position=1)]
	  [string] $ResourceGroup,

	  [string] $RegionFilter = " US",

	  [int] $MaxCount = 10     
	)

	Write-Host
@'
 _____ _           _ _____                     
|     | |___ _ _ _| | __  |___ ___ ___ ___ ___ 
|   --| | . | | | . |    -| .'|  _| . | . |   |
|_____|_|___|___|___|__|__|__,|___|___|___|_|_|
    Cloud IP Hunting - Proof of Concept [Azure]         
'@
	try{
		Connect-AzAccount
	}catch{
		Write-Error 'Failed to call Connect-AzAccount'
		return $False
	}

	if ((Get-AzResource | ? {$_.ResourceGroupName -eq $ResourceGroup}).Length -eq 0){
		Write-Error "$($ResourceGroup) is no valid"
		return $False		
	}
	
	$response = curl "https://securitytrails.com/list/ip/1.1.1.1" -SessionVariable session
	if (-not $response.Content -match 'csrf_token = "(\S+?)"'){
		Write-Error 'Failed to get CSRF token'
		return $False	
	}

	$response.Content -match 'csrf_token = "(\S+?)"'
	$csrf_body = @{_csrf_token=$Matches[1]} | ConvertTo-Json

	Write-Host "[+] Connected to Azure. Hunting ...`n"

	$Locations = Get-AzLocation | ? {$_.DisplayName -like "*$($RegionFilter)*"} | select -exp Location

	1..$MaxCount | % {

		$GeneratedName = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})

		$Addr = New-AzPublicIpAddress -AllocationMethod Static -ResourceGroupName $ResourceGroup -Name $GeneratedName -Location (Get-Random $Locations) -WarningAction SilentlyContinue

		Write-Host "[+] Checking $($Addr.IpAddress)"

		$response = curl "https://securitytrails.com/app/api/v1/list?ipv4=$($Addr.IpAddress)" -Method POST -Body $csrf_body -ContentType "application/json" -WebSession $session

		if ($response.Content["records"].Count -gt 0){

			Write-Host '[+] Found an interesting record:'
			Write-Host $Addr
			Write-Host $response.Content["records"]

		}else{
			$Addr | Remove-AzPublicIpAddress -Force
		}
	}

}