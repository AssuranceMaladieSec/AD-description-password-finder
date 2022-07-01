Import-Module ActiveDirectory

$current_dir = Get-Location
$OutputFile = "$current_dir\output\desc.csv"
Write-Host "Requesting domain controller to retrieve all accounts with description"
Set-Location AD:

foreach ($elem in (Get-ADUser  -Filter '*' -Properties SamAccountName, Description | Select-Object SamAccountName, Description)){
	if ($elem.Description){
		$elem |Export-CSV -Path $OutputFile -Delimiter ";" -Append -Encoding utf8 -NoTypeInformation
	}
}

Write-Host "Done! Powershell results to be processed are written in $OutputFile"
Set-Location $current_dir