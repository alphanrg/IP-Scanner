### Ping range of IP's

# Check if parameters are given and exit if
# syntax is false or parameters do not exist
param([string]$P, [string]$IP1, [string]$IP2);

$nl = [Environment]::NewLine
if (($PSBoundParameters.values | Measure-Object | Select-Object -ExpandProperty Count) -lt 1) {
	Write-Host "Exiting script, no arguments specified.";
	Write-Host "Error!$nl";
	Write-Host 'Examples: .\IP-Scanner.ps1 -IP1 "192.168.1.0" -IP2 "192.168.1.255"';
	Write-Host '          .\IP-Scanner.ps1 -IP1 "192.168.1.0"';
	Write-Host "Written by Joris Piepers in 2014"
	Break;
}

# IP address check function
function Validation([string]$IP) {
	if (($IP.split('.') | measure | select -exp count) -eq 4) {
		for ($i = 0; $i -le 3; $i++) {
			$convert = ($IP.split('.')[$i]);
			if ($convert -match "^[0-9\s]+$") {
				if (($convert.substring(0,1) -eq 0) -and ($convert.length -gt 1) -and ($convert.substring(1,1) -ge $convert.substring(0,1))) {
					Write-Host "IP address invalid.";
					Write-Host "Error!";
					return $false;
					break;
				}
				$segment = [int]$convert;
				if ($segment -gt 256) {
					Write-Host "IP address invalid.";
					Write-Host "Error!";
					return $false;
					break;
				}
			} else {
				Write-Host "IP address invalid.";
				Write-Host "Error!";
				return $false;
				break;
			}
		}
	}
	return $true;
}

function CheckRange([string]$FIP, [string]$SIP) {
	$IP1 = [int]($FIP.split('.')[0]);
	$IP2 = [int]($SIP.split('.')[0]);
	if ($IP1 -eq $IP2) {
		for ($i = 1; $i -le 3; $i++) {
			$IP1 = [int]($FIP.split('.')[$i]);
			$IP2 = [int]($SIP.split('.')[$i]);
			if ($IP1 -ne $IP2) {
				$Class += "$i";
				if ($Class -eq "13") {
					Write-Host "Illegal ip range.";
					return $false;
					break;
				}
			}
			if ($IP1 -le $IP2) {
				if ($i -eq 3) {
					return $true;
				}
			} else {
				Write-Host "Illegal ip range.";
				return $false;
				break;
			}
		}
	}
}

function Multi([string]$FIP, [string]$SIP) {
	$Range = @();
	$StaticIP = @();
	# Find static IP segments and put them in array
	for ($i = 0; $i -le 3; $i++) {
		$IP1 = [int]($FIP.split('.')[$i]);
		$IP2 = [int]($SIP.split('.')[$i]);
		if ($IP1 -ne $IP2) {
			$Range += [int]($FIP.split('.')[$i]);
			$Range += [int]($SIP.split('.')[$i]);
		} else {
			$StaticIP += ($FIP.split('.')[$i]);
		}
	}

	# Check if segments and length of ip range is valid
	if ((([int]$StaticIP.Length + [int]$Range.Length/2) -eq 4)) {
		# Compile static IP segments
		foreach ($Segment in $StaticIP) {
			$IP += $Segment + ".";
		}

		# Print change ip range
		switch ($Range.Length) {
			# Class A network
			6 {
				Write-Host "Executing class A network ping test:`r`n";
				$Start = 0;
				$End = 0;
				$Start += ((Get-Date).Hour * 3600);
				$Start += ((Get-Date).Minute * 60);
				$Start += ((Get-Date).Second);
				foreach ($Segment01 in ($Range[0]..$Range[1])) {
					foreach ($Segment02 in ($Range[2]..$Range[3])) {
						foreach ($Segment03 in ($Range[4]..$Range[5])) {
							if (Test-Connection "$IP$Segment01.$Segment02.$Segment03" -Count 1 -Quiet) {
								$Name = ((Resolve-DnsName "$IP$Segment01.$Segment02.$Segment03").NameHost);
								if ($Name) {
									write-host "$IP$Segment01.$Segment02.$Segment03		Ping okay!		$Name";
								} else {
									write-host "$IP$Segment01.$Segment02.$Segment03		Ping okay!";
								}
							}
						}
					}
				}
				$End += ((Get-Date).Hour * 3600);
				$End += ((Get-Date).Minute * 60);
				$End += ((Get-Date).Second);
				$Result = ($End - $Start);
				Write-Host "`r`nPing test finished in $Result secs.";
			}
			# Class B network
			4 {
				Write-Host "Executing class B network ping test:`r`n";
				$Start = 0;
				$End = 0;
				$Start += ((Get-Date).Hour * 3600);
				$Start += ((Get-Date).Minute * 60);
				$Start += ((Get-Date).Second);
				foreach ($Segment01 in ($Range[0]..$Range[1])) {
					foreach ($Segment02 in ($Range[2]..$Range[3])) {
						if (Test-Connection "$IP$Segment01.$Segment02" -Count 1 -Quiet) {
							$Name = ((Resolve-DnsName "$IP$Segment01.$Segment02").NameHost);
							if ($Name) {
								write-host "$IP$Segment01.$Segment02		Ping okay!		$Name";
							} else {
								write-host "$IP$Segment01.$Segment02		Ping okay!";
							}
						}
					}
				}
				$End += ((Get-Date).Hour * 3600);
				$End += ((Get-Date).Minute * 60);
				$End += ((Get-Date).Second);
				$Result = ($End - $Start);
				Write-Host "`r`nPing test finished in $Result secs.";
			}
			# Class C network
			2 {
				Write-Host "Executing class C network ping test:`r`n";
				$Start = 0;
				$End = 0;
				$Start += ((Get-Date).Hour * 3600);
				$Start += ((Get-Date).Minute * 60);
				$Start += ((Get-Date).Second);
				foreach ($Number in ($Range[0]..$Range[1])) {
					if (Test-Connection $IP$Number -Count 1 -Quiet) {
						$Name = ((Resolve-DnsName "$IP$Number").NameHost);
						if ($Name) {
							write-host "$IP$Number		Ping okay!		$Name";
						} else {
							write-host "$IP$Number		Ping okay!";
						}
					}
				}
				$End += ((Get-Date).Hour * 3600);
				$End += ((Get-Date).Minute * 60);
				$End += ((Get-Date).Second);
				$Result = ($End - $Start);
				Write-Host "`r`nPing test finished in $Result secs.";
			}
		}
	}
}

function Single([string]$IP) {
	Write-Host "Executing ping to single IP:`r`n";
	$Start = 0;
	$End = 0;
	$Start += ((Get-Date).Hour * 3600);
	$Start += ((Get-Date).Minute * 60);
	$Start += ((Get-Date).Second);
	if (Test-Connection "$IP" -Count 1 -Quiet) {
		write-host "$IP		Ping okay!";
	} else {
		write-host "$IP		Ping failed!";
	}
	$End += ((Get-Date).Hour * 3600);
	$End += ((Get-Date).Minute * 60);
	$End += ((Get-Date).Second);
	$Result = ($End - $Start);
	Write-Host "`r`nPing test finished in $Result secs.";
}

clear-host;
$IP01 = (Validation($IP1));
$IP02 = (Validation($IP2));
$ErrorActionPreference= 'silentlycontinue'
if ($IP1 -and $IP2) {
	$equal = (CheckRange($IP1) ($IP2));
	if ($equal) {
		(Multi($IP1) ($IP2));
	}
} elseif ($IP1 -and !$IP2) {
	(Single($IP1));
} elseif ($IP2) {
	(Single($IP2));
} else {
	Write-Host "Error.";
}