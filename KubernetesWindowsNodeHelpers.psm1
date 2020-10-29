function DownloadAndExpandTarGzArchive {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [Uri] $Url,
        [Parameter(Position = 1)]
        [string] $DestinationPath = '.'
    )

    Process {
        try {
            $TgzFile = New-TemporaryFile
            DownloadFile -Url $Url -Destination $TgzFile -Force
            tar -xkf $TgzFile -C $DestinationPath
            Remove-Item $TgzFile
        } catch {
            throw
        }
    }
}

function DownloadAndExpandZipArchive {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [Uri] $Url,
        [Parameter(Position = 1)]
        [string] $DestinationPath = '.'
    )

    Process {
        try {
            $ZipFile = New-TemporaryFile | Rename-Item -NewName { $_ -replace 'tmp$','zip' } -PassThru
            DownloadFile -Url $Url -Destination $ZipFile -Force
            Expand-Archive $ZipFile.FullName $DestinationPath
            Remove-Item $ZipFile
        } catch {
            throw
        }
    }
}

function DownloadFile {
    Param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [Uri] $Url,
        [Parameter(Position = 1)]
        [string] $Destination,
        [switch] $Force
    )

    Process {
        if (!($Force -and $Force.IsPresent) -and $Destination -and (Test-Path $Destination)) {
            Write-Host "[DownloadFile] File '$Destination' already exists."
            return
        }

        try {
            if (!$Destination) {
                curl.exe -L $Url | ForEach-Object -Begin { $result = New-Object System.Text.StringBuilder } -Process { $result = $result.Append($_) } -End { $result.ToString() }
            } else {
                curl.exe -L $Url -o $Destination
                Write-Host "Downloaded [$Url] => [$Destination]"
            }
        } catch {
            Write-Error "Failed to download '$Url'"
            throw
        }
    }
}

function ValidateKubernetesWindowsNodeConfiguration {
    [CmdletBinding()]
    Param ()

    Begin {
        [string[]] $Errors = @()
    }

    Process {
        if (!$Script:Config.Kubernetes) {
            $Errors += "'Kubernetes' section is missing in the configuration file!"
        } else {
            if (!$Script:Config.Kubernetes.ControlPlane) {
                $Errors += "'Kubernetes.ControlPlane' section is missing in the configuration file!"
            }
            
            if (!$Script:Config.PSObject.TypeNames -contains 'KubernetesClusterNodeConfiguration') {
                $Script:Config.PSObject.TypeNames.Add('KubernetesClusterNodeConfiguration')
            }

            if (!$Script:Config.Kubernetes.Version) {
                $Script:Config.Kubernetes = $Script:Config.Kubernetes | Add-Configuration 'Version' '1.19.0' -Force
                Write-Host "'Kubernetes.Version' was not specified. Using 'v$($Script:Config.Kubernetes.Version)'".
            }

            if (!$Script:Config.Node.InterfaceName) {
                $Script:Config.Node | Add-Configuration 'InterfaceName' 'Ethernet' -Force
                $Script:Config.Node | Add-Configuration 'IPAddress' (Get-InterfaceIPAddress -InterfaceName $InterfaceName) -Force
                $Script:Config.Node | Add-Configuration 'Subnet' (Get-InterfaceSubnet -InterfaceName $InterfaceName) -Force
                $Script:Config.Node | Add-Configuration 'DefaultGateway' (Get-InterfaceDefaultGateway -InterfaceName $InterfaceName) -Force
                Write-Host "'Node.InterfaceName' was not specified. Using '$($Script:Config.Node.InterfaceName)'."
            }

            if (!$Script:Config.Cri) {
                $Script:Config | Add-Configuration 'Cri' ([PSCustomObject]@{ Name = 'dockerd' }) -Force
                Write-Host "'Cri.Name' was not specified. Using '$($Script:Config.Cri.Name)'."
            }

            if (!$Script:Config.Cni) {
                $Script:Config | Add-Configuration 'Cni' ([PSCustomObject]@{
                    NetworkMode = 'overlay'
                    NetworkName = 'vxlan0'
                    Version = '0.8.7'
                    Plugin = [PSCustomObject]@{
                        Name = $CniPluginName          # e.g. flannel, kubenet
                        Version = $CniPluginVersion.ToLower().TrimStart('v')
                        InstallPath = $CniPluginInstallPath
                    }
                }) -Force
                Write-Host "The 'Cni' section was not specified. Using the following settings:`r`n`r`n$($Script:Config.Cni | ConvertTo-JSON)`r`n"
            }

            if (!$Script:Config.Cni.NetworkMode) {
                $Errors += 'Missing ''Cni.NetworkMode'' configuration setting. Must be one of ''l2bridge'' or ''overlay''.'
            }

            if (!$Script:Config.Cni.NetworkName) {
                if ($Script:Config.Cni.NetworkMode -eq 'overlay') {
                    $Script:Config.Cni | Add-Configuration 'NetworkName' 'vxlan0' -Force
                } elseif ($Script:Config.Cni.NetworkMode -eq 'l2bridge') {
                    $Script:Config.Cni | Add-Configuration 'NetworkName' 'cbr0' -Force
                }
            }

            if (!$Script:Config.Cni.Version) {
                $Script:Config.Cni | Add-Configuration 'Version' '0.8.7' -Force
                Write-Host "'Cni.Version' was not specified. Using 'v$($Script:Config.Cni.Version)'."
            }

            if (!$Script:Config.Cni.Plugin) {
                $Script:Config.Cni | Add-Configuration 'Plugin' ([PSCustomObject]@{
                    Name = 'flannel'
                    Version = '0.13.0'
                })
                Write-Host "A 'Cni.Plugin' was not specified. Using '$($Script:Config.Cni.Plugin.Name) v$($Script:Config.Cni.Plugin.Version)'."
            }
                
            if (!$Script:Config.Cni.Plugin.Name) {
                $Errors += 'Missing ''Cni.Plugin.Name''. Must be one of ''flannel'' or ''kubenet''.'
            }

            if ($Script:Config.Cni.Plugin.Name -eq 'flannel') {
                if (!$Script:Config.Cni.Plugin.Version) {
                    $Script:Config.Cni.Plugin | Add-Configuration 'Version' '0.13.0'
                    Write-Host "A 'Cni.Plugin.Version' was not specified for '$($Script:Config.Cni.Plugin.Name)'. Using 'v$($Script:Config.Cni.Plugin.Version)'."
                }
            } else {
                $Errors += 'Missing ''Cni.Plugin.Version''.'
            }

            if (!$Script:Config.Images) {
                $Script:Config | Add-Configuration 'Images' ([PSCustomObject]@{
                    NanoServer = "mcr.microsoft.com/windows/nanoserver:$Script:WinVer"
                    ServerCore = "mcr.microsoft.com/windows/servercore:$Script:WinVer"
                })

                $Script:Config.Images | Add-Configuration 'Infrastructure' $(if ($Script:WinVer -notmatch '^10\.0\.17763') {
                    [PSCustomObject]@{
                        Build = $True
                        FlannelDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile'
                        KubeProxyDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/kube-proxy/Dockerfile'
                        PauseDockerfile = 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'
                    }
                } else {
                    $InfrastructureImages = [PSCustomObject]@{
                        Build = $False
                        Pause = 'mcr.microsoft.com/oss/kubernetes/pause:1.3.0'
                    }
                })

                Write-Host 'An ''Images'' section was not found. Using the following images:'
                Write-Host "    Windows Nano Server: $($Script:Config.Images.NanoServer)"
                Write-Host "    Windows Server Core: $($Script:Config.Images.ServerCore)"
                Write-Host "    Infrastructure images:"
                if ($Script:WinVer -notmatch '^10\.0\.17763') {
                    Write-Host "        Custom images must be built because existing images don't support this version of Windows."
                    Write-Host "        Flannel: $($Script:Config.Images.Infrastructure.FlannelDockerfile)"
                    Write-Host "        Kube-Proxy: $($Script:Config.Images.Infrastructure.KubeProxyDockerfile)"
                    Write-Host "        Pause: $($Script:Config.Images.Infrastructure.PauseDockerfile)"
                } else {
                    Write-Host "        Pause: $($Script:Config.Images.Infrastructure.Pause)"
                }
            }

            if (!$Script:Config.Images.NanoServer) {
                $Script:Config.Images | Add-Configuration 'NanoServer' "mcr.microsoft.com/windows/nanoserver:$Script:WinVer"
                Write-Host "'Images.NanoServer' was not specified. Using '$($Script:Config.Images.NanoServer)'."
            }

            if (!$Script:Config.Images.ServerCore) {
                $Script:Config.Images | Add-Configuration 'ServerCore' "mcr.microsoft.com/windows/servercore:$Script:WinVer"
                Write-Host "'Images.ServerCore' was not specified. Using '$($Script:Config.Images.ServerCore)'."
            }

            if (!$Script:Config.Images.Infrastructure) {
                $Script:Config.Images | Add-Configuration 'Infrastructure' $(if ($Script:WinVer -notmatch '^10\.0\.17763') {
                    [PSCustomObject]@{
                        Build = $True
                        FlannelDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile'
                        KubeProxyDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/kube-proxy/Dockerfile'
                        PauseDockerfile = 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'
                    }
                } else {
                    $InfrastructureImages = [PSCustomObject]@{
                        Build = $False
                        Pause = 'mcr.microsoft.com/oss/kubernetes/pause:1.3.0'
                    }
                })

                Write-Host 'An ''Images'' section was not found. Using the following images:'
                Write-Host "    Windows Nano Server: $($Script:Config.Images.NanoServer)"
                Write-Host "    Windows Server Core: $($Script:Config.Images.ServerCore)"
                Write-Host "    Infrastructure images:"
                if ($Script:WinVer -notmatch '^10\.0\.17763') {
                    Write-Host "        Custom images must be built because existing images don't support this version of Windows."
                    Write-Host "        Flannel: $($Script:Config.Images.Infrastructure.FlannelDockerfile)"
                    Write-Host "        Kube-Proxy: $($Script:Config.Images.Infrastructure.KubeProxyDockerfile)"
                    Write-Host "        Pause: $($Script:Config.Images.Infrastructure.PauseDockerfile)"
                } else {
                    Write-Host "        Pause: $($Script:Config.Images.Infrastructure.Pause)"
                }
            }

            if (!$Script:Config.Kubernetes.Network) {
                $Script:Config.Kubernetes | Add-Configuration 'Network' ([PSCustomObject]@{
                    ClusterCIDR = '10.244.0.0/16'
                    ServiceCIDR = '10.96.0.0/12'
                    DnsServiceIPAddress = '10.96.0.10'
                })
                Write-Host '''Kubernetes.Network'' was not specified. Using the following network settings:'
                Write-Host "    Cluster CIDR:           $($Script:Config.Kubernetes.Network.ClusterCIDR)"
                Write-Host "    Service CIDR:           $($Script:Config.Kubernetes.Network.SerivceCIDR)"
                Write-Host "    DNS Service IP Address: $($Script:Config.Kubernetes.Network.DnsServiceIPAddress)`r`n"
            }

            if (!$Script:Config.Kubernetes.Network.ClusterCIDR) {
                $Errors += 'Missing ''Kubernetes.Network.ClusterCIDR''.'
            }

            if (!$Script:Config.Kubernetes.Network.ServiceCIDR) {
                $Errors += 'Missing ''Kubernetes.Network.ServiceCIDR''.'
            }

            if (!$Script:Config.Kubernetes.Network.DnsServiceIPAddress) {
                $Errors += 'Missing ''Kubernetes.Network.DnsServiceIPAddress''.'
            }

            if (!$Script:Config.Wins) {
                $Script:Config | Add-Configuration 'Wins' ([PSCustomObject]@{ Version = 'latest' })
                Write-Host '''Wins.Value'' was not specifified. Using version ''latest'' of Wins.'
            }
        }
    }

    End {
        if ($Errors.Length -gt 0) {
            throw "Errors were encountered while validating the Kubernetes Node Configuration file:`r`n$($Errors | ForEach-Object { "    $_" })"
        }
    }
}

function WaitForNetwork {
    Param (
        [Parameter(Position = 0)]
        [string] $NetworkName = 'vxlan0',

        [Parameter(Position = 1)]
        [int] $TimeoutSeconds = 60
    )

    $StartTime = Get-Date

    while ($True) {
        [TimeSpan] $ElapsedTime = $(Get-Date) - $StartTime
        if ($ElapsedTime.TotalSeconds -ge $TimeoutSeconds) {
            throw "Failed to create the network '$NetworkName' in $TimeoutSeconds seconds"
        }

        if ((Get-HnsNetwork | Where-Object { $_.Name -eq $NetworkName.ToLower() })) { break }

        Write-Host "Waiting for the network '$NetworkName' to be created by flanneld..."
        Start-Sleep 5
    }
}

function Add-Configuration {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [string] $Name,
        [Parameter(Position = 1, Mandatory)]
        [object] $Value,
        [Parameter(Mandatory, ValueFromPipeline)]
        $InputObject,
        [Management.Automation.PSMemberTypes] $MemberType = [Management.Automation.PSMemberTypes]::NoteProperty,
        [switch] $PassThru,
        [switch] $Force
    )

    Process {
        $ConfigSection | Add-Member -MemberType $MemberType -Name $Name -Value $Value -PassThru:$PassThru -Force:$Force
    }
}

function ConvertTo-IPAddress {
    Param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [UInt32[]] $Address
    )

    Process {
        foreach ($a in $Address) {
            $(foreach ($i in 0..3) {
                $Divisor = [Math]::Pow(256, 3 - $i)
                $Remainder = $a % $Divisor
                ($a - $Remainder) / $Divisor
                $a = $Remainder
            }) -join '.'
        }
    }
}

function ConvertTo-IntegerIPAddress {
    Param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [Net.IPAddress[]] $IPAddress
    )

    Process {
        foreach ($addr in $IPAddress) {
            $i = 3;
            $addr.GetAddressBytes() | ForEach-Object -Begin {
                [Uint32] $IntegerIP = 0;
                $i = 3
            } -Process {
                $IntegerIP += $_ * [Math]::Pow(256, $i--)
            } -End {
                $IntegerIP
            }
        }
    }
}   

<#
.SYNOPSIS

Copies your SSH key to another machine and adds it to the Autherized SSK Keys file
(typically ~/.ssh/authorized_keys).

.PARAMETER PublicSshKeyPath

The path and filename of the public SSH key to copy.

.PARAMETER RemoteUsername

The username with which to connect to the remote machine and to which to add the
public SSH key as an authorized key.

.PARAMETER RemoteHostname

The name of the remote host to connect to.

#>
function Copy-SshKey {
    Param (
        [Parameter(Position = 0)]
        [string] $PublicSshKeyPath = "${env:USERPROFILE}\.ssh\id_rsa.pub",

        [Parameter(Position = 1, Mandatory)]
        [string] $RemoteUsername,

        [Parameter(Position = 2, Mandatory)]
        [string] $RemoteHostname,

        [Parameter(Position = 3)]
        [int] $Port
    )

    Process {
        $AddAuthorizedKeyCommand = "PUB_KEY=\`"$(Get-Content $PublicSshKeyPath)\`" ; grep -q -F \`"`$PUB_KEY\`" ~/.ssh/authorized_keys 2>/dev/null || echo \`"`$PUB_KEY\`" >> ~/.ssh/authorized_keys"
        ssh -T "${RemoteUsername}@${RemoteHostname}$(if ($Port) { ":$Port" })" $AddAuthorizedKeyCommand
    }
}

function Get-ApiServerEndpoint {
    (ConvertFrom-JSON $(kubectl.exe get endpoints --all-namespaces -o json | Out-String)).Items | Where-Object {
        $_.Metadata.Name -eq 'kubernetes'
    } | ForEach-Object {
        "$($_.subsets[0].addresses[0].ip):$($_.subsets[0].ports[0].port)"
    }
}

function Get-CniBinaries {
    Param (
        [string] $Path = (Join-Path $Script:KubernetesClusterNodeInstallationPath 'cni'),
        [string] $Version = '0.8.7',
        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay',
        [ValidateSet('flannel','kubenet')]
        [string] $PluginName = 'flannel',
        [string] $PluginVersion = '0.13.0',
        [switch] $Force
    )

    Process {
        $Script:CniPath = $Path
        $Script:CniConfigurationPath = (Join-Path $Script:CniPath 'config')

        if (($Force -or $Force.IsPrenent) -and (Test-Path $Script:CniPath)) {
            Remove-Item -Path $Script:CniPath -Recurse -Force
        }

        if (!(Test-Path $Script:CniConfigurationPath)) {
            $null = New-Item -ItemType Directory $Script:CniConfigurationPath
        }

        if (!(Test-Path $Script:CniPath)) {
            DownloadAndExpandTarGzArchive -Url "https://github.com/containernetworking/plugins/releases/download/v$Version/cni-plugins-windows-amd64-v$Version.tgz" -DestinationPath $Script:CniPath -ErrorAction Stop
            Write-Host "Downloaded CNI binaries for the '$NetworkMode' network mode to '$Script:CniPath'."

            DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/$NetworkMode/cni/config/cni.conf" $Script:CniConfigurationPath  -ErrorAction Stop -Force:$Force
            Write-Host "Downloaded default CNI configuration from GitHub at Microsoft/SDN."

            if ($PluginName -ieq 'flannel') {
                Get-FlanneldBinaries -Version $PluginVersion -Force:$Force
            } else {
                throw "The '$PluginName' Container Network Interface (CNI) plugin is not supported yet."
            }
        }
    }
}

function Get-DockerImage {
    Param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [string[]] $Image
    )

    Process {
        foreach ($i in $Image) {
            if (!(docker images $i -q)) {
                docker image pull $i
                if (!(docker images $i -q)) {
                    throw "Failed to pull '$i'"
                }

                if ($i -imatch 'nanoserver|servercore') {
                    docker tag $i $($i -ireplace '(nanoserver|servercore):.*','$1:latest')
                } elseif ($i -imatch 'pause') {
                    docker tag $i 'kubeletwin/pause'
                }
            }
        }
    }
}

function Get-FlanneldBinaries {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [string] $Version,
        [string] $Destination = 'C:\flannel',
        [switch] $Force
    )

    Process {
        if ($Force -and $Force.IsPresent -and (Test_Path $Destination)) {
            Remove-Item -Path $Destination -Recurse -Force
        }

        if (!(Test-Path $Destination)) {
            $null = New-Item -ItemType Directory $Destination
        }

        DownloadFile -Url "https://github.com/coreos/flannel/releases/download/v$Version/flanneld.exe" -Destination (Join-Path $Destination 'flanneld.exe') -Force:$Force -ErrorAction Stop
        Write-Host "Finished downloading Flanneld v$Version to '$Destination'"
    }
}

function Get-GolangVersionMetadata {
    [CmdletBinding()]
    [OutputType('GoLang.VersionMetadata')]
    Param (
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidatePattern('(?i)\d+\.\d+\.\d+|latest')]
        [string[]] $Version = 'latest',

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('amd64','arm32v7','arm64v8','i386','ppc64le','s390x','src','windows-amd64')]
        [string[]] $Architecture = 'windows-amd64'
    )

    Begin {
        $GoLangVersionInfo = Invoke-RestMethod -Method GET -Uri 'https://raw.githubusercontent.com/docker-library/golang/master/versions.json' -ErrorAction Stop
    }

    Process {
        foreach ($v in $Version) {
            $GoLangVersionKey = $(
                if ($v -ne 'latest') {
                    $MajorMinorVersion = $v -replace '^(\d+\.\d+).*$','$1'

                    $GoLangVersionInfo.PSObject.Properties |
                        Select-Object -ExpandProperty Name |
                        Where-Object { $_ -eq $MajorMinorVersion } |
                        Select-Object -First 1
                } else {
                    $GoLangVersionInfo.PSObject.Properties |
                        Select-Object -Last 1 -ExpandProperty Name
                }
            )

            $GoLangVersionMetadata = $GoLangVersionInfo.$GoLangVersionKey

            foreach ($a in $Architecture) {
                $a = $a.ToLower();

                $GoLangArchVersionInfo = $GoLangVersionMetadata.arches.$a
                [PSCustomObject]@{
                    PSTypeName = 'GoLang.VersionMetadata'
                    Version = $GoLangVersionMetadata.version
                    Arch = $GoLangArchVersionInfo.arch
                    Sha256 = $GoLangArchVersionInfo.sha256
                    Url = $GoLangArchVersionInfo.url
                }
            }
        }
    }
}

function Get-HnsScriptModule {
    Param (
        [string] $Path = $Script:KubernetesClusterNodeInstallationPath,
        [switch] $Force
    )

    Process {
        Write-Host "Downloading Windows HNS helper scripts..."
        $Destination = Join-Path $Path 'hns.psm1'
        DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1" -Destination $Destination -Force:$Force
    }
}

function Get-InterfaceDefaultGateway {
    Param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [string[]] $InterfaceName = 'Ethernet'
    )

    Process {
        foreach ($n in $InterfaceName) {
            (Get-NetAdapter -InterfaceAlias $InterfaceName | Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop
        }
    }
}

function Get-InterfaceIPAddress {
    Param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [string[]] $InterfaceName = 'Ethernet'
    )

    Process {
        foreach ($n in $InterfaceName) {
            Get-NetIpAddress -AddressFamily IPv4 -InterfaceAlias $n | Select-Object -ExpandProperty IPAddress
        }
    }
}

function Get-InterfaceSubnet {
    Param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [string[]] $InterfaceName = 'Ethernet'
    )

    Process {
        foreach ($n in $InterfaceName) {
            $NetAdapter = Get-NetAdapter -InterfaceAlias $n -ErrorAction Stop
            $IpAddress = Get-NetIpAddress -AddressFamily IPv4 -InterfaceIndex $NetAdapter.InterfaceIndex | Select-Object -ExpandProperty IPAddress
            $SubnetMask = (Get-CimInstance -ClassName 'WIN32_NETWORKADAPTERCONFIGURATION' | Where-Object { $_.InterfaceIndex -eq $NetAdapter.InterfaceIndex }).IPSubnet[0]
        
            "$(ConvertTo-IPAddress ((ConvertTo-IntegerIPAddress $IpAddress) -band (ConvertTo-IntegerIPAddress $SubnetMask)))/$(Get-SubnetMaskLength $SubnetMask)"
        }
    }
}

function Get-KubernetesBinaries {
    Param (
        [Parameter(Position = 0)]
        [string] $Path = $Script:KubernetesClusterNodeInstallationPath,

        [Parameter(Position = 1)]
        [string] $Version = '1.19.0',

        [switch] $Force
    )

    Process {
        try {
            if ((Test-Path (Join-Path (Join-Path (Join-Path (Join-Path $Path kubernetes) node) bin) kubectl.exe)) -and $Force -or $Force.IsPresent) {
                Remove-Item -Path (Join-Path $Path kubernetes) -Recurse -Force
            }

            if (!(Test-Path (Join-Path $Path kubernetes))) {
                Write-Host "Downloading Kubernetes v$Version..."
                DownloadAndExpandTarGzArchive -Url "https://dl.k8s.io/v$Version/kubernetes-node-windows-amd64.tar.gz" -DestinationPath $Path
                Write-Host "Finished downloading Kubernetes v$Version"
            
                $KubernetesBinariesPath = Join-Path (Join-Path (Join-Path $Path 'kubernetes') 'node') 'bin'
                if ($env:PATH -inotmatch [Regex]::Escape($KubernetesBinariesPath)) {
                    $env:PATH = "${env:PATH};$KubernetesBinariesPath"
                    [Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::Machine)
                    Write-Host "Added Kubernetes executables to the PATH"
                }
            }
        } catch {
            Write-Host 'Failed to download kuberenetes!'
            throw
        }
    }
}

function Get-KubernetesClusterConfiguration {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [string] $MasterAddress,
        [Parameter(Position = 1, Mandatory)]
        [string] $MasterUsername
    )

    Process {
        $KubernetesClusterConfigurationPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'config'
        
        scp -o StrictHostKeyChecking=no "$($MasterUsername)@$($MasterAddress):~/.kube/config" $KubernetesClusterConfigurationPath
        if (!$?) {
            Write-Error "Failed to download kubernetes cluster configuration!"
        } else {
            Write-Host "Retrieved Kubernetes cluster configuration from '$MasterAddress'..."
        }

        Write-Host "Setting KUBECONFIG environment variable..."
        $env:KUBECONFIG = $KubernetesClusterConfigurationPath
        [Environment]::SetEnvironmentVariable("KUBECONFIG", $env:KUBECONFIG, [EnvironmentVariableTarget]::Machine)
    }
}

function Get-KubernetesWindowsNodeConfiguration {
    [OutputType('KubernetesWindowsNodeConfiguration')]
    Param(
        [Parameter(Position = 0)]
        [string] $Path = $Script:KubernetesClusterNodeConfigurationPath
    )

    $NodeConfig = $null

    if (Test-Path $Path) {
        $NodeConfig = Get-Content $Path -Encoding UTF8 -Raw | ConvertFrom-JSON
        if ('KubernetesWindowsNodeConfiguration' -notin $NodeConfig.PSObject.TypeNames) {
            $null = $NodeConfig.PSObject.TypeNames.Add('KubernetesWindowsNodeConfiguration')
        }
    }

    $NodeConfig
}

function Get-SourceVip {
    Param (
        [Parameter(Position = 0)]
        [string] $Path = $Script:KubernetesClusterNodeInstallationPath,

        [Parameter(Position = 1)]
        [string] $CniPath = $Script:CniPath,

        [Parameter(Position = 2)]
        [string] $NetworkName = 'vxlan0'
    )

    $SourceVipPath = Join-Path $Path 'sourceVip.json'
    $SourceVipReqeuestPath = Join-Path $Path 'sourceVipRequest.json'

    $HnsNetwork = Get-HnsNetwork | Where-Object { $_.Name -eq $NetworkName.ToLower() }
    $HnsNetworkSubnet = $HnsNetwork.Subnets[0].AddressPrefix

    $IpamConfig = @"
{
    "cniVersion": "0.2.0",
    "name": "vxlan0",
    "ipam": {
        "type": "host-local",
        "ranges": [
            [
                {
                    "subnet": "$HnsNetworkSubnet"
                }
            ]
        ],
        "dataDir": "/var/lib/cni/networks"
    }
}
"@

    $IpamConfig | Out-File $SourceVipRequestPath

    $CurrentLocation = $PWD
    $env:CNI_COMMAND = 'ADD'
    $env:CNI_CONTAINERID= 'dummy'
    $env:CNI_NETNS='dummy'
    $env:CNI_IFNAME = 'dummy'
    $env:CNI_PATH = $CniPath

    Set-Location $env:CNI_PATH
    Get-Content $SourceVipRequest | .\host-local.exe | Out-File $SourceVipPath
    $SourceVip = Get-Content $SourceVipJson | ConvertFrom-JSON

    Remove-Item env:\CNI_COMMAND
    Remove-Item env:\CNI_CONTAINERD
    Remove-Item env:\CNI_NETNS
    Remove-Item env:\CNI_IFNAME
    Remove-Item env:\CNI_PATH

    Set-Location $CurrentLocation

    ($SourceVip.ip4.ip -split '/')[0]
}

function Get-SubnetMaskLength {
    Param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [Net.IPAddress[]] $SubnetMask
    )

    Process {
        foreach ($mask in $SubnetMask) {
            ("$($mask.GetAddressBytes() | ForEach-Object {
                [Convert]::ToString($_, 2) # Converts $_ no binary representation
            })" -replace '[\s0]').Length
        }
    }
}

function Get-WindowsBuildVersion {
    [Cmdletbinding()]
    [OutputType([string])]
    Param()

    (& cmd /c ver)[1] -replace '.*\[Version (.*)\]','$1'
}

function Install-ContainerNetworkInterface {
    [CmdletBinding()]
    Param (
        [string] $InterfaceName = 'Ethernet',

        [string] $NetworkConfigurationPath = $Script:NetworkConfigurationPath,

        [ValidateSet('flannel','kubenet')]
        [string] $CniPluginName = 'flannel',

        [string] $CniPluginVersion = '0.13.0',

        [string] $CniPluginInstallationPath = 'C:\flannel',

        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay',

        [string] $NetworkName = 'vxlan0',

        [string] $ClusterCIDR = '10.244.0.0/16',

        [string] $KubeConfig = $env:KUBECONFIG
    )

    Process {
        $NetworkMode = $NetworkMode.ToLower()
        $NetworkName = $NetworkName.ToLower()

        switch ($CniPluginName) {
            'kubenet' {
                Write-Error "'$CniPluginName' is not yet supported."
                return
            }

            'flannel' {
                if (!(Get-Service Flanneld -ErrorAction SilentlyContinue)) {
                    # Need to stop the Kubelet service so that we can update the CNI and kubernetes node network configuration
                    Stop-Service Kubelet -WarningAction SilentlyContinue -ErrorAction Stop

                    Set-NetConfig -Path $NetworkConfigurationPath -NetworkMode $NetworkMode -NetworkName $NetworkName -ClusterCIDR $ClusterCIDR -ErrorAction Stop
                                
                    New-KubernetesNetwork -InterfaceName $InterfaceName -NetworkMode $NetworkMode -ErrorAction Stop

                    $FlannelDInterfaceName = $(
                        $NetworkAdatpter = Get-NetAdapter -InterfaceAlias "vEthernet ($InterfaceName)" -ErrorAction SilentlyContinue
                        if ($NetworkAdapter) {
                            $NetworkAdapter.InterfaceAlias
                        } else {
                            $Script:Config.Node.InterfaceName
                        }
                    )

                    Install-Flanneld -Path $CniPluginInstallationPath -NetworkConfigurationPath $NetworkConfigurationPath -Version $CniPluginVersion -InterfaceName (Get-NetAdapter -InterfaceAlias "vEthernet ($InterfaceName)" -ErrorAction SilentlyContinue).InterfaceAlias -KubeConfig $KubeConfig -ErrorAction Stop

                    break
                }
            }
        }
    }
}

function Install-ContainerRuntimeInterface {
    [CmdletBinding()]
    Param (
        [ValidateSet('dockerd','containerd')]
        [string] $Name = 'dockerd',

        [switch] $Force
    )

    switch ($Name) {
        'dockerd' { Install-Dockerd -Force:$Force }

        'containerd' {
            throw "The ContainerD CRI is not supported at this time."
            #Install-ContainerD -Force:$Force
            break
        }
    }
}

function Install-ContainersFeature {
    [OutputType([Boolean])]
    Param ( [switch] $Force )

    if (!(Get-WindowsFeature -Name 'containers').Installed) {
        if (!($Force -and $Force.IsPresent)) {
            Write-Host "The Containers feature is not installed on this machine. It is required to configure this server as a Kubernetes node."
            Write-Host "Installing Windows Defender will require this machine to be restarted before the Kubernetes node can be configured."

            $resp = Read-HostEx -Prompt "Install the Containers feature? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
        }

        if (($Force -and $Force.IsPresent) -or !$resp -or $resp -ieq 'y') {
            Install-WindowsFeature -Name 'Containers'
            Write-Host "The Containers feature has been uninstalled from this machine."
            $True
        }
    } else {
        $False
    }
}

function Install-Dockerd {
    Param( [switch] $Force )

    if (!(Get-Package -Name docker -ProviderName DockerMsftProvider)) {
        if (!($Force -and $Force.IsPresent)) {
            Write-Host "Docker wes not found on this machine."
            $Resp = Read-HostEx "Install Docker and necessary prerequisites on this machine? [Y/n] (Default 'Y') " -ExpectedValue 'Y', 'n'
        }

        if (($Force -and $Force.IsPresent) -or !$rsep -or $resp -ieq 'y') {
            Write-Host "Installing Docker and any necessary prerequisites..."

            if (!(Get-PackageProvider -Name NuGet)) {
                Write-Host "    The NuGet package provider was not found on this machine. Installing ..."
                Install-PackageProvider -Name NuGet -Force -ErrorAction Stop
                Write-Host "    The NuGet package provider has been installed on this machine."
            } else {
                Write-Host "    The NuGet package provider is already installed."
            }

            if (!(Get-Module -Name DockerMsftProvider)) {
                Write-Host "    The 'DockerMsftProvider' PowerShell module was not found on this machine. Installing ..."
                Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
                Write-Host "    The DockerMsftProvider PowerShell module has been installed on this machine."
            } else {
                Write-Host "    The DockerMsftProvider PowerShell module is already installed."
                Write-Host "    Checking for DockerMsftProvider PowerShell module updates..."
                Update-Module -Name DockerMsftProvider -Force
                Write-Host "    Updated the DockerMsftProvider PowerShell module to the latest version."
            }

            Write-Host "    Installing Docker..."
            Install-Package -Name docker -ProviderName DockerMsftProvider -Force
            Write-Host "Docker has been installed on this machine."
        } else {
            Write-Host "This server cannot be configured as a Kubernetes cluster node unless Docker is installed."
            return
        }
    } else {
        Write-Host "Docker has already been installed on this machine."
    }
}

function Install-Flanneld {
    [CmdletBinding()]
    [OutputType([System.ServiceProcess.ServiceController])]
    Param (
        [string] $Path = 'C:\flannel',

        [string] $NetworkConfigurationPath = $Script:NetworkConfigurationPath,

        [string] $LogPath = (Join-Path $Script:KubernetesClusterNodeLogPath 'flanneld'),

        [string] $Version = '0.13.0',

        [string] $InterfaceName = 'vEthernet (Ethernet)',

        [string] $KubeConfig = $env:KUBECONFIG
    )

    Process {
        Write-Host "Installing FlannelD to '$Path'..."

        if (!(Test-Path $LogPath)) {
            $null = New-Item -ItemType Directory -Path $LogPath
        }

        Get-FlanneldBinaries -Destination $Path -Version $Version

        $FlanneldSvc = Get-Service Flanneld -ErrorAction SilentlyContinue
        if (!$FlanneldSvc) {
            $FlanneldCommandLine = @(
                $(Join-Path $Path 'flanneld.exe')
                "--kubeconfig-file=`"$KubeConfig`""
                "--net-config-path=`"$NetworkConfigurationPath`""
                "--iface=`"$InterfaceName`""
                "--ip-masq=1"
                "--kube-subnet-mgr=1"
            )

            $null = New-ServiceEx -Name 'Flanneld' -CommandLine $FlanneldCommandLine -DependsOn 'kubelet' -LogFilePath (Join-Path $LogPath 'flanneldsvc.log') -EnvironmentVariable @{ 'NODE_NAME' = $env:COMPUTERNAME.ToLower() }
        }

        # The newly created service is disposed, so just query for the object again.
        Get-Service -Name 'Flanneld'
    }
}

function Install-Kubelet {
    [CmdletBinding()]
    Param (
        [string] $CniConfigurationPath = $Script:CniConfigurationPath,
        [string] $CniPath = $Script:CniPath,
        [ValidateSet('flannel','kubenet')]
        [string] $CniPluginName = 'flannel',

        [ValidateSet('containerd','dockerd')]
        [string] $CriName = 'dockerd',

        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay',

        [string] $NetworkName = 'vxlan0',

        [string] $NodeIpAddress = (Get-InterfaceIpAddress),
        [string] $NodeSubnet = (Get-InterfaceSubnet),

        [string] $KubeConfig = $env:KUBECONFIG,

        [string] $ClusterCIDR = '10.244.0.0/16',

        [string] $ServiceCIDR = '10.96.0.0/12',

        [string] $DnsServiceIpAddress = '10.96.0.10',
        
        [string[]] $FeatureGates
    )

    Process {
        if (!(Test-Path $Script:KubernetesClusterNodeLogPath)) {
            $null = New-Item -ItemType Directory -Path $Script:KubernetesClusterNodeLogPath
        }

        if (!(Get-Service 'kubelet' -ErrorAction SilentlyContinue)) {
            Set-CniConfiguration -Path $CniConfigurationPath -NodeIpAddress $NodeIpAddress -NodeSubnet $NodeSubnet -PluginName $CniPluginName -NetworkMode $NetworkMode -NetworkName $NetworkName -ClusterCIDR $ClusterCIDR -ServiceCIDR $ServiceCIDR -ErrorAction Stop

            $KubeletArgs = @(
                (Get-Command 'kubelet.exe' -ErrorAction Stop).Source
                '--windows-service'
                '--v=6'
                "--log-dir=`"$Script:KubernetesClusterNodeLogPath`""
                "--cert-dir=`"$env:SYSTEMDRIVE\var\lib\kubelet\pki`""
                "--cni-bin-dir=`"$CniPath`""
                "--cni-conf-dir=`"$CniConfigurationPath`""
                '--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf'
                "--kubeconfig=$KubeConfig"
                "--hostname-override=$($env:COMPUTERNAME.ToLower())"
                '--pod-infra-container-image=kubeletwin/pause'
                '--enable-debugging-handlers'
                '--cgroups-per-qos=false'
                '--enforce-node-allocatable=""'
                '--logtostderr=false'
                '--network-plugin=cni'
                '--resolv-conf=""'
                "--cluster-dns=`"$DnsServiceIpAddress`""
                '--cluster-domain=cluster.local'
            )

            if ($FeatureGates) {
                $KubeletArgs += "--feature-gates=$($FeatureGates -join ',')"
            }

            New-Service -Name 'kubelet' -StartupType Automatic -DependsOn 'docker' `
                -BinaryPathName "$KubeletArgs"

            if (!(Get-NetFirewallRule -Name KubeletAllow10250 -ErrorAction SilentlyContinue)) {
                $null = New-NetFirewallRule -Name KubeletAllow10250 -Description "Kubelet Allow 10250" -Action Allow -LocalPort 10250 -Protocol TCP -Enabled True -DisplayName "Kubelet Allow 10250 (TCP)" -ErrorAction Stop
            }

            Get-Service -Name 'Kubelet'
        }
    }
}

function Install-KubeProxy {
    [CmdletBinding()]
    Param (
        [string] $KubeProxypConfigPath = $(Join-Path $Script:KubernetesClusterNodeInstallationPath 'kubeproxy.conf'),

        [string] $KubeProxyLogPath = $(Join-Path $Script:KubernetesClusterNodeLogPath 'kube-proxy'),

        [string] $KubeConfig = $env:KUBECONFIG,

        [string] $NetworkName = 'vxlan0',

        [object] $SourceVip,

        [string] $ClusterCIDR = '10.244.0.0/16',

        [string[]] $FeatureGates
    )

    Process {
        if (!(Get-Service 'kubeproxy' -ErrorAction SilentlyContinue)) {
            $NetworkName = $NetworkName.ToLower()

            if (!(Test-Path $KubeProxyConfigPath)) {
                $null = New-Item -ItemType Directory -Path $KubeProxyConfigPath
            }

            if (!(Test-Path $KubeProxyLogPath)) {
                $null = New-Item -ItemType Directory -Path $KubeProxyLogPath
            }

            $KubeProxyConfiguration = @{
                Kind = 'KubeProxyConfiguration'
                apiVersion = 'kubeproxy.config.k8s.io/v1alpha1'
                hostnameOverride = $env:COMPUTERNAME
                clusterCIDR = $ClusterCIDR
                clientConnection = @{
                    kubeconfig = $KubeConfig
                }
                winkernel = @{
                    enableDsr = 'WinDSR=true' -iin $FeatureGates
                    networkName = $NetworkName
                }
            }

            Write-Host "Installing Kubeproxy as a service..."
        
            $KubeProxyArgs = @(
                (Get-Command kube-proxy.exe -ErrorAction Stop).Source
                "--hostname-override=${env:COMPUTERNAME}"
                '--v=6'
                '--proxy-mode=kernelspace'
                "--kubeconfig=`"$KubeConfig`""
                "--network-name=$NetworkName"
                "--cluster-cidr=$ClusterCIDR"
                "--log-dir=`"$KubeProxyLogPath`""
                '--logtostderr=false'
                '--windows-service'
            )

            if ('WinDSR=true' -iin $FeatureGates) {
                $KubeProxyArgs += '--enable-dsr=true'
            }

            if ($SourceVip) {
                $KubeProxyArgs += "--source-vip=$(ConvertFrom-JSON $SourceVip -Compress)"
                $KubeProxyConfiguration.winkernel += @{
                    sourceVip = $SourceVip;
                }
            }

            if ($FeatureGates) {
                $KubeProxyArgs += "--feature-gates=$($FeatureGates -join ',')"
            }

            ConvertTo-JSON -Depth 100 $KubeProxyConfiguration | Out-File $KubeProxyConfigPath

            New-Service -Name 'kubeproxy' -StartupType Automatic -DisplayName 'KubeProxy' -Description 'KubeProxy Kubernetes Service' -BinaryPathName "$KubeProxyArgs" |
                Start-Service -ErrorAction Stop
        }
    }
}

function Install-RancherWins {
    [CmdletBinding()]
    Param (
        [string] $Path = $Script:WinsPath,
        [string] $Version = 'latest',
        [switch] $Force
    )

    Process {
        $WinsSvc = Get-Service rancher-wins -ErrorAction SilentlyContinue
        if (!$WinsSvc) {
            $Version = switch -Regex ($Version) {
                '(?i)^latest$' {
                    (Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/rancher/wins/releases/latest' -ErrorAction Stop).'tag_name'
                }

                '^v?\d+\.\d+\.\d+$' {
                    $_.ToLower().TrimStart('v')
                }

                default {
                    Write-Error "'$Version' is not a valid version specification."
                }
            }

            DownloadFile -Url "https://github.com/rancher/wins/releases/download/$Version/wins.exe" -Destination (Join-Path $Path 'wins.exe') -Force:$Force -ErrorAction Stop
        
            if ($env:PATH -inotmatch 'C:\wins;') {
                $env:PATH = "$env:PATH;C:\wins" -replace ';;'
                [Environment]::SetEnvironmentVariable('PATH',$env:PATH,[EnvironmentVariableTarget]::Machine)
            }

            # Register wins as a service
            wins.exe srv app run --register

            $WinsSvc = Get-Service rancher-wins
        }

        if ($WinsSvc.Status -ne 'Running') {
            $WinsSvc | Start-Service
        }
    }
}

# TODO: Add parameters for the working directory...maybe other stuff...this cmdlet has A LOT of assumptions baked into it.....
function Join-KubernetesCluster {
    $Script:Config = Get-KubernetesWindowsNodeConfiguration

    $null = Import-Module "$Script:KubernetesClusterNodeInstallationPath\hns.psm1" -WarningAction 'SilentlyContinue'

    if (!$Script:Config) {
        Write-Error "Unable to find '$Script:KubernetesClusterNodeConfigurationPath'. Please create a kubernetes node configuration file using New-KubernetesClusterNodeConfiguration."
        return
    }

    if (!($env:KUBECONFIG -and (Test-Path $env:KUBECONFIG -ErrorAction SilentlyContinue))) {
        Get-KubernetesClusterConfiguration -MasterAddress ($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+$') -MasterUsername $Script:Config.Kubernetes.ControlPlane.Username
    }

    $Script:KubernetesClusterConfiguration = $env:KUBECONFIG

    if ($Script:Config.Cni.NetworkMode -ine 'overlay') {
        $env:KUBE_NETWORK = $Script:Config.Cni.NetworkName.ToLower()
        [Environment]::SetEnvironmentVariable('KUBE_NETWORK', $env:KUBE_NETWORK, [EnvironmentVariableTarget]::Machine)
    }

    Install-RancherWins -Path $Script:WinsPath -Version $Script:Config.Wins.Version
    Write-Host "Rancher Wins has been installed as a Windows Service."

    $InstallKubeletParams = @{
        CniPath = $Script:CniPath
        CniConfigurationPath = $Script:CniConfigurationPath
        CniPluginName = $Script:Config.Cni.Plugin.Name
        CriName = $Script:Config.Cri.Name
        NetworkMode = $Script:Config.Cni.NetworkMode
        NetworkName = $Script:Config.Cni.NetworkName
        NodeIpAddress = $Script:Config.Node.IPAddress
        NodeSubnet = $Script:Config.Node.Subnet
        KubeConfig = $env:KUBECONFIG
        ClusterCIDR = $Script:Config.Kubernetes.Network.ClusterCIDR
        ServiceCIDR = $Script:Config.Kubernetes.Network.ServiceCIDR
        DnsServiceIpAddress = $Script:Config.Kubernetes.Network.DnsServiceIpAddress
        FeatureGates = $Script:Config.Kubernetes.Kubelet.FeatureGates
    }
    Install-Kubelet -ErrorAction Stop @InstallKubeletParams
    Write-Host "Installed Kubelet as a Windows Service"
    
    $InstallCNIParams = @{
        InterfaceName = $(
            $NetworkAdatpter = Get-NetAdapter -InterfaceAlias "vEthernet ($($Script:Config.Node.InterfaceName))" -ErrorAction SilentlyContinue
            if ($NetworkAdapter) {
                $NetworkAdapter.InterfaceAlias
            } else {
                $Script:Config.Node.InterfaceName
            }
        )
        NetworkConfigurationPath = $Script:NetworkConfigurationPath
        CniPluginName = $Script:Config.Cni.Plugin.Name
        CniPluginVersion = $Script:Config.Cni.Plugin.Version
        NetworkMode = $Script:Config.Cni.NetworkMode
        NetworkName = $Script:Config.Cni.NetworkName
        ClusterCIDR = $Script:Config.Kubernetes.Network.ClusterCIDR
        KubeConfig = $env:KUBECONFIG
    }
    Install-ContainerNetworkInterface -ErrorAction Stop @InstallCNIParams
    Write-Host "Finished installing the Container Network Interface (CNI)."

    kubeadm.exe join "$(Get-ApiServerEndpoint)" --token $Script:Config.Kubernetes.ControlPlane.JoinToken --discovery-token-ca-cert-hash "$($Script:Config.Kubernetes.ControlPlane.CAHash)"
    if (!$?) {
        Write-Error "Error joining cluster!"
        return
    }

    WaitForNetwork $NetworkName

    if (!(Test-NodeRunning)) {
        throw "Kubelet is not running and/or failed to bootstrap."
    }
    
    $KubeProxyInstallParams = @{
        NetworkName = $Script:Config.Cni.NetworkName
        ClusterCIDR = $Script:Config.Kubernetes.Network.ClusterCIDR
        FeatureGates = $Script:Config.Kubernetes.KubeProxy.FeatureGates
    }
    if ($Script:Config.Cni.NetworkMode -ieq 'overlay') {
        $KubeProxyInstallParams += @{ SourceVip = (Get-SourceVip -NetworkName $Script:Config.Cni.NetworkName) }
    }
    Install-KubeProxy -ErrorAction Stop @KubeProxyInstallParams
    Write-Host "Installed Kube-Proxy as a Windows Service"

    kubectl.exe get nodes

    Write-Host "Node $($env:COMPUTERNAME) successfully joined the cluster."
}

function New-GoLangContainerImage {
    [CmdletBinding()]
    Param (
        [PSTypeName('GoLang.VersionMetadata')]
        [PSCustomObject] $GoLangVersionMetadata = (Get-GoLangVersionMetadata),
        [switch] $Force
    )

    Process {
        if ($Force -and $Force.IsPresent) {
            # Remove the old image so it gets rebuilt
            $null = docker image rm -f $(docker images golang -q | Select-Object -First 1) -ErrorAction Ignore
        }

        if (!(docker images golang -q)) {
            $Version = $GoLangVersionMetadata.Version

            $Tags = @(
                "$Version-windowsservercore-$Script:WinVer"
                "$Version-windowsservercore"
                "$Version"
            ) | ForEach-Object { "golang:$_" }

            $LatestGfwReleasePage = DownloadFile -Url 'https://github.com/git-for-windows/git/releases/latest'
            $result = $LatestGfwReleasePage -match '<td>MinGit-(?<Version>\d+\.\d+\.\d+)-64-bit\.zip</td>\s*<td>(?<Hash>.*?)</td>'
            if (!$result) {
                Write-Error "Unable to find the latest Git for Windows MinGit release version number or it's SHA-256 authenticity hash in order to build a custom GoLang Docker container image which is required for building OS-specific Kuberenetes infrastructure docker container images."
                return
            }

            $LatestMinGitGfwReleaseVersion = $Matches.Version
            $LatestMinGitGfwReleaseHash = $Matches.Hash
        
            $GoLangDockerfileTemplate = Invoke-RestMethod -Method GET -Uri 'https://raw.githubusercontent.com/docker-library/golang/master/Dockerfile-windows-servercore.template' -ErrorAction Stop
            $GoLangDockerfileTemplate `
                -replace '\{\{\s*env\.WindowsVariant\s*\}\}:\{\{\s*env\.WindowsRelease\s*\}\}', "servercore:$Script:WinVer" `
                -replace 'SHELL \[.*?\]', 'SHELL ["powershell", "-NoLogo", "-NonInteractive", "-Command", "$ErrorActionPreference = ''Stop''; $ProgressPreference = ''SilentlyContinue'';"]' `
                -replace 'ENV GIT_VERSION\s+', "ARG GIT_VERSION=" `
                -replace 'ENV GIT_DOWNLOAD_SHA256\s+', "ARG GIT_DOWNLOAD_SHA256=" `
                -replace 'ENV GOLANG_VERSION\s+(\{\{\s*\.version\s*\}\})', @'
ARG GOLANG_VERSION="$1"
ARG GOLANG_DOWNLOAD_URL
ARG GOLANG_DOWNLOAD_SHA256
'@ `
                -replace '''\{\{\s*\.arches\["windows-amd64"\]\.url\s*\}\}''', '$env:GOLANG_DOWNLOAD_URL' `
                -replace '''\{\{\s*\.arches\["windows-amd64"\]\.sha256\s*\}\}''', '$env:GOLANG_DOWNLOAD_SHA256' |
                Set-Content golang.dockerfile -ErrorAction Stop

            docker build --build-arg GIT_VERSION=$LatestMinGitGfwReleaseVersion --build-arg GIT_DOWNLOAD_SHA256=$LatestMinGitGfwReleaseHash --build-arg GOLANG_VERSION=$Version --build-arg GOLANG_DOWNLOAD_URL=$($GoLangVersionMetadata.Url) --build-arg GOLANG_DOWNLOAD_SHA256=$($GoLangVersionMetadata.Sha256) -t $Tags[0] -t $Tags[1] -t $Tags[2] -f golang.dockerfile .
            if (!(docker images golang -q)) {
                Write-Error "Failed to build Golang docker container image."
            }
        } else {
            Write-Host "Using the existing Docker image for Go: 'golang:$Version-windowsservercore-$Script:WinVer'."
        }
    }
}

function New-KubernetesFlannelContainerImage {
    [CmdletBinding()]
    Param (
        [string] $GoLangDockerImageTag = "$((Get-GoLangVersionMetadata).Version)-windowsservercore-$Script:WinVer",
        [string] $FlannelDockerfile = 'https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/flannel/Dockerfile',
        [string] $FlannelVersion = '0.13.0',
        [string] $CniVersion = '0.8.7',
        [switch] $Force
    )

    Process {
        $Tags = @(
            "$FlannelVersion-windowsservercore-$Script:WinVer"
            "$FlannelVersion-windowsservercore"
            $FlannelVersion
        ) | ForEach-Object { "kubeletwin/flannel:$_" }

        if ($Force -and $Force.IsPresent) {
            # Remove the old images
            $null = docker images $Tags[0] -q | ForEach-Object { docker images rm $_ -f }
        }

        if (!(docker images $Tags[0] -q)) {
            $WorkingDir = Join-Path $PWD flannel

            if (!(Test-Path $WorkingDir)) {
                $null = New-Item -ItemType Directory -Path $WorkingDir
            }

            $OriginalLocation = Get-Location
            try {
                Set-Location $WorkingDir

                Get-HnsScriptModule -Path $PWD
                Invoke-RestMethod -Method GET -Uri ($FlannelDockerfile -replace 'Dockerfile$','setup.go') -OutFile setup.go

                # Get the latest version number/tag of yq from GitHub:
                $YqLatestReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/mikefarah/yq/releases/latest' -ErrorAction Stop
                $LatestYqVersion = $YqLatestReleaseMetadata.'tag_name'

                # Get the latest version number/tag of wins from GitHum:
                $WinsLatestReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/rancher/wins/releases/latest' -ErrorAction Stop
                $LatestWinsVersion = $WinsLatestReleaseMetadata.'tag_name'

                # Getting the dockerfile separately because we need to modify it...see below.
                $FlannelDockerfileContent = Invoke-RestMethod -Method GET -Uri $FlannelDockerfile

                # Update the dockerfile so we can dynamically specify the version of flannel to use
                $FlannelDockerfileContent = $FlannelDockerfileContent `
                    -replace 'ARG cniVersion\r?\n', @'
ARG flannelVersion=0.13.0
ARG cniVersion="0.8.5"
ARG winsVersion="v0.0.4"
ARG yqVersion="2.4.1"
ENV FLANNEL_DOWNLOAD_URL https://github.com/coreos/flannel/releases/download/v${flannelVersion}/flanneld.exe

'@ `
                    -replace '(pushd C:\\k\\flannel; \\)\r?\n\s*curl\.exe.*?/flanneld\.exe', @'
$1
  Write-Host ('Downloading Flannel v{0} from {1}...' -f $env:flannelVersion, $env:FLANNEL_DOWNLOAD_URL); \
  curl.exe -LO ${env:FLANNEL_DOWNLOAD_URL}
'@ `
                    -replace '(pushd c:\\cni; \\)', @'
$1
  Write-Host ('Downloading CNI plugins release v{0}...' -f $env:cniVersion); \
'@ `
                    -replace '(mkdir C:\\utils; \\)', @'
$1
  Write-Host ('Downloading rancher wins {0}...' -f $env:winsVersion); \
'@ `
                    -replace 'wins/releases/download/v0\.0\.4/wins', 'wins/releases/download/${env:winsVersion}/wins' `
                    -replace '(curl.exe -Lo C:\\utils.*/yq_windows_amd64\.exe;\s+\\)', @'
Write-Host ('Downloading yq v{0}...' -f $env:yqVersion); \
  $1
'@ `
                    -replace 'yq/releases/download/2\.4\.1/yq_windows_amd64','yq/releases/download/${env:yqVersion}/yq_windows_amd64' |
                    Set-Content Dockerfile -ErrorAction Stop

                Write-Host @"
About to execute:

docker build --build-arg servercoreTag=$Script:WinVer --build-arg cniVersion=$CniVersion --build-arg golangTag=$GoLangDockerImageTag --build-arg flannelVersion=$FlannelVersion --build-arg yqVersion=$LatestYqVersion --build-arg winsVersion=$LatestWinsVersion -t kubeletwin/flannel:${FlannelVersion}-windowsservercore-$Script:WinVer -t kubeletwin/flannel:$FlannelVersion -t kubeletwin/flannel:latest .

"@

                docker build --build-arg servercoreTag=$Script:WinVer --build-arg cniVersion=$CniVersion --build-arg golangTag=$GoLangDockerImageTag --build-arg flannelVersion=$FlannelVersion --build-arg yqVersion=$LatestYqVersion --build-arg winsVersion=$LatestWinsVersion -t $Tags[0] -t $Tags[1] -t $Tags[2] .
                if (!(docker images 'kubeletwin/flannel' -q)) {
                    Write-Error "Failed to build Kubernetes Windows Flannel v$FlannelVersion docker container networking image."
                }
            } finally {
                Set-Location $OriginalLocation
            }
        }
    }
}

function New-KubernetesKubeProxyContainerImage {
    [CmdletBinding()]
    Param (
        [string] $KubeProxyDockerfile = 'https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kube-proxy/Dockerfile',
        [string] $KubernetesVersion = '1.19.3',
        [switch] $Force
    )

    Process {
        $Tags = @(
            "${KubernetesVersion}-windowsservercore-$Script:WinVer"
            "${KubernetesVersion}-windowsservercore"
            $KubernetesVersion
        ) | ForEach-Object { "kubeletwin/kube-proxy:$_" }

        if ($Force -and $Force.IsPresent) {
            # Remove the old images
            $null = docker images $Tags[0] -q | ForEach-Object { docker images rm $_ -f } -ErrorAction SilentlyContinue
        }

        if (!(docker images $Tags[0] -q)) {
            # Get the latest version number/tag of yq from GitHub:
            $YqLatestReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/mikefarah/yq/releases/latest' -ErrorAction Stop
            $LatestYqVersion = $YqLatestReleaseMetadata.'tag_name'

            # Get the latest version number/tag of wins from GitHum:
            $WinsLatestReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/rancher/wins/releases/latest' -ErrorAction Stop
            $LatestWinsVersion = $WinsLatestReleaseMetadata.'tag_name'

            # Getting the dockerfile separately because we need to modify it...see below.
            $KubeProxyDockerfileContent = Invoke-RestMethod -Method GET -Uri $KubeProxyDockerfile

            # Update the dockerfile so we can dynamically specify the version of flannel to use
            $KubeProxyDockerfileContent `
                -replace '(ARG k8sVersion)\r?\n', @'
$1
ARG winsVersion="v0.0.4"
ARG yqVersion="2.4.1"

'@ `
                -replace '(pushd C:\\k\\kube-proxy; \\)', @'
$1
  Write-Host ('Downloading Kube-Proxy {0}...' -f $env:k8sVersion); \
'@ `
                -replace '(mkdir C:\\utils; \\)', @'
$1
  Write-Host ('Downloading rancher wins {0}...' -f $env:winsVersion); \
'@ `
                -replace 'wins/releases/download/v0\.0\.4/wins', 'wins/releases/download/${env:winsVersion}/wins' `
                -replace '(curl.exe -sLo C:\\utils.*/yq_windows_amd64\.exe;\s+\\)', @'
Write-Host ('Downloading yq v{0}...' -f $env:yqVersion); \
  $1
'@ `
                -replace 'yq/releases/download/2\.4\.1/yq_windows_amd64','yq/releases/download/${env:yqVersion}/yq_windows_amd64' |
                Set-Content Dockerfile -ErrorAction Stop

            docker build --build-arg k8sVersion=v$KubernetesVersion --build-arg servercoreTag=$Script:WinVer --build-arg winsVersion=$LatestWinsVersion --build-arg yqVersion=$LatestYqVersion -t $Tags[0] -t $Tags[1] -t $Tags[2] .
            if (!(docker images 'kubeletwin/kube-proxy' -q)) {
                Write-Error "Failed to build Kubernetes Windows kube-proxy docker container imaage."
            }
        }
    }
}

function New-KubernetesNetwork {
    Param (
        [string] $InterfaceName = 'Ethernet',

        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay'
    )

    $NetworkMode = $NetworkMode.ToLower()

    $HnsNetwork = Get-HnsNetwork | Where-Object { $_.Name -eq 'External' }

    if ($NetworkMode -eq 'l2bridge') {
        if (!$HnsNetwork) {
            New-HnsNetwork -Type $NetworkMode -AddressPrefix '192.168.255.0/30' -Gateway '192.168.255.1' -Name 'External' -AdapterName $InterfaceName
        }
    } else {
        New-NetFirewallRule -Name 'OverlayTraffic4789UDP' -Description 'Overlay network traffic (UDP)' -Action Allow -LocalPort 4789 -Enabled True -DisplayName 'Overlay Traffic 4789 UDP (Inbound)' -Protocol UDP -ErrorAction SilentlyContinue
        if (!$HnsNetwork) {
            New-HnsNetwork -Type $NetworkMode -AddressPrefix '192.168.255.0/30' -Gateway '192.168.255.1' -Name 'External' -AdapterName $InterfaceName -SubnetPolicies @(@{ Type = 'VSID'; VSID = 9999 })
        }
    }
}

function New-KubernetesPauseContainerImage {
    Param (
        [string] $Dockerfile,
        [switch] $Force
    )

    Process {

        if ($Force -and $Force.IsPresent) {
            # Remove the old image
            $null = docker images 'kubeletwin/pause' -q | ForEach-Object { docker images rm $_ -f } -ErrorAction Stop
        }

        if (!(docker images 'kubeletwin/pause' -q)) {
            docker build -t 'kubeletwin/pause' "$Dockerfile"
            if (!(docker images 'kubeletwin/pause' -q)) {
                Write-Error "Failed to build Kubernetes Windows infrastructure 'pause' docker container image."
            }
        }
    }
}

function New-KubernetesWindowsNodeConfiguration {
    [OutputType('KubernetesWindowsNodeConfiguration')]
    Param (
        [validateSet('flannel','kubenet')]
        [string] $CniPluginName = 'flannel',

        [string] $CniPluginVersion = '0.13.0',

        [string] $CniVersion = '0.8.7',

        [ValidateSet('containerd','dockerd')]
        [string] $Cri = 'dockerd',
        
        [string] $InterfaceName = 'Ethernet',

        [Parameter(Mandatory)]
        [string] $KubeadmCAHash,

        [Parameter(Mandatory)]
        [string] $KubeadmJoinToken,
        
        [string] $KubeClusterCIDR = '10.244.0.0/16',

        [string] $KubeDnsServiceIPAddress = '10.96.0.10',

        [string[]] $KubeletFeatureGates = '',

        [string[]] $KubeProxyGates = 'WinOverlay=true',

        [string] $KubeServiceCIDR = '10.96.0.0/12',
        
        [string] $KubernetesVersion = '1.19.3',

        [Parameter(Mandatory)]
        [string] $MasterAddress,

        [Parameter(Mandatory)]
        [string] $MasterUsername,

        [string] $NanoServerImage,

        [ValidateSet('l2bridge','overlay')]
        [string] $NetworkMode = 'overlay',

        [string] $NetworkName = 'vxlan0',

        [string] $PauseImage,

        [string] $ServerCoreImage,

        [string] $WinsVersion = 'latest'
    )

    if (!$NanoServerImage) {
        $NanoServerImage = "mcr.microsoft.com/windows/nanoserver:$WinVer" -replace '\s+'
    }

    if (!$ServerCoreImage) {
        $ServerCoreImage = "mcr.microsoft.com/windows/servercore:$WinVer" -replace '\s+'
    }

    # If you're using a version of Windows Server 2019 that is not LTSC2019 (or 1809), 1903, or 1909,
    # then the standard kube-flannel and kube-proxy images will not run on your OS version. Alse need
    # to build a custom kubernetes infrastructure image (Pause image) in this case.
    #
    # Otherwise, we can use the standard images.
    #
    if ($Script:WinVer -notmatch '^10\.0\.17763') {
        $InfrastructureImages = [PSCustomObject]@{
            Build = $True
            FlannelDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile'
            KubeProxyDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/kube-proxy/Dockerfile'
            PauseDockerfile = 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'
        }
    } else {
        $InfrastructureImages = [PSCustomObject]@{
            Build = $False
            Pause = 'mcr.microsoft.com/oss/kubernetes/pause:1.3.0'
        }
    }

    $Script:Config = [PSCustomObject]@{
        PSTypeName = 'KubernetesWindowsNodeConfiguration'
        Cri = [PSCustomObject]@{
            Name = $Cri
        }
        Cni = [PSCustomObject]@{
            NetworkMode = $NetworkMode.ToLower()  # e.g. l2bridge, overlay
            NetworkName = $NetworkName.ToLower()  # e.g. vxlan0
            Version = $CniVersion.ToLower().TrimStart('v')
            Plugin = [PSCustomObject]@{
                Name = $CniPluginName          # e.g. flannel, kubenet
                Version = $CniPluginVersion.ToLower().TrimStart('v')
                WindowsNodeConfigurationUrl = $(if ($CniPluginName -ieq 'flannel') {
                    "https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/flannel/flannel-$(if ($NetworkMode -ieq 'overlay') { 'overlay' } else { 'host-gw' }).yml"
                })
            }
        }
        Images = [PSCustomObject] @{
            NanoServer = $NanoServerImage
            ServerCore = $ServerCoreImage
            Infrastructure = $InfrastructureImages
        }
        Kubernetes = [PSCustomObject]@{
            Version = $KubernetesVersion.ToLower().TrimStart('v')
            ControlPlane = [PSCustomObject]@{
                Address = $MasterAddress
                Username = $MasterUsername
                JoinToken = $KubeadmJoinToken
                CAHash = $KubeadmCAHash
            }
            Kubelet = [PSCustomObject]@{
                FeatureGates = [string[]]@($KubeletFeatureGates)
            }
            KubeProxy = [PSCustomObject]@{
                FeatureGates = [string[]]@($KubeProxyGates)
                WindowsNodeConfigurationUrl = 'https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/kube-proxy/kube-proxy.yml'
            }
            Network = [PSCustomObject]@{
                ClusterCIDR = $KubeClusterCIDR
                ServiceCIDR = $KubeServiceCIDR
                DnsServiceIPAddress = $KubeDnsServiceIPAddress
            }
        }
        Node = [PSCustomObject]@{
            InterfaceName = $InterfaceName
            IPAddress = Get-InterfaceIPAddress -InterfaceName $InterfaceName
            Subnet = Get-InterfaceSubnet -InterfaceName $InterfaceName
            DefaultGateway = Get-InterfaceDefaultGateway -InterfaceName $InterfaceName
        }
        Wins = [PSCustomObject]@{
            Version = $WinsVersion.ToLower().TrimStart('v')
        }
    }

    $Script:Config
}

function New-ServiceEx {
    [OutputType([System.ServiceProcess.ServiceController])]
    Param (
        [Parameter(Position = 0, Mandatory)]
        [string] $Name,

        [Parameter(Position = 1, Mandatory)]
        [string[]] $CommandLine,

        [string[]] $DependsOn,

        [Parameter(Mandatory)]
        [string] $LogFilePath,

        [hashtable] $EnvironmentVariable
    )

    Process {
        $WrappedServiceExe = New-ServiceWrapper -Name $Name -CommandLine $CommandLine -LogFile $LogFilePath -EnvironmentVariable $EnvironmentVariable

        $Service = New-Service -Name $Name -BinaryPathName $WrappedServiceExe -DependsOn $DependsOn -DisplayName $Name -StartupType Automatic -Description "$Name Kubernetes Service"

        Write-Host @"

++++++++++++++++++++++++++++++++
Successfully created the service
++++++++++++++++++++++++++++++++
Service     : [$Name]
Command Line: [$CommandLine]
Environment : [$($EnvironmentVariable | ConvertTo-JSON)]
Log File    : [$LogFilePath]
Deponds On  : [$($DependsOn -join ', ')]
+++++++++++++++++++++++++++++++++

"@

        $Service
    }
}

function New-ServiceWrapper {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [string] $Name,

        [Parameter(Position = 1, Mandatory)]
        [string[]] $CommandLine,

        [Parameter(Position = 2, Mandatory)]
        [string] $LogFile,

        [Hashtable] $EnvironmentVariable
    )

    $ServiceExe = $CommandLine[0] -replace '\\', '\\' # Replace a single '\' with '\\'
    $ServiceArgs = $CommandLine | Select-Object -Skip 1 | ForEach-Object { $_ -replace '\\', '\\' -replace '"', '\"' }
    $WrappedServiceExe = Join-Path (Split-Path $CommandLine[0] -Parent) "${Name}Svc.exe"
    $LogFile = $LogFile -replace '\\', '\\'

    Write-Host "Creating a wrapper SCM service binary for [$Name] [$CommandLine] => [$WrappedServiceExe]..."
    $ServiceSrc = @"
using System;
using System.ComponentModel;
using System.IO;
using System.ServiceProcess;
using System.Diagnostics;
using System.Runtime.InteropServices;

public enum ServiceType {
    SERVICE_WIN32_OWN_PROCESS   = 0x00000010,
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020
}

public enum ServiceState {
    SERVICE_STOPPED          = 0x00000001,
    SERVICE_START_PENDING    = 0x00000002,
    SERVICE_STOP_PENDING     = 0x00000003,
    SERVICE_RUNNING          = 0x00000004,
    SERVICE_CONTINUE_PENDING = 0x00000005,
    SERVICE_PAUSE_PENDING    = 0x00000006,
    SERVICE_PAUSED           = 0x00000007
}

[StructLayout(LayoutKind.Sequential)]
public struct ServiceStatus {
    public ServiceType dwServiceType;
    public ServiceState dwCurrentState;
    public int dwControlsAccepted;
    public int dwWin32ExitCode;
    public int dwServiceSpecificExitCode;
    public int dwCheckPoint;
    public int dwWaitHint;
};

public class ${Name}ScmService : ServiceBase {
    private ServiceStatus m_serviceStatus;
    private Process m_process;
    private StreamWriter m_writer = null;
    private EventLog m_eventLog;

    public ${Name}ScmService() {
        ServiceName = "${Name}";
        CanStop = true;
        CanPauseAndContinue = false;

        m_eventLog = new EventLog();
        if (!EventLog.SourceExists(ServiceName)) {
            EventLog.CreateEventSource(ServiceName, "System");
        }
        m_eventLog.Source = ServiceName;
        m_eventLog.Log = "System";

        m_writer = new StreamWriter("$LogFile");
        Console.SetOut(m_writer);
        Console.WriteLine("$ServiceExe ${Name}ScmService()");
    }

    ~${Name}ScmService() {
        if (m_writer != null) m_writer.Dispose();
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool SetServiceStatus(IntPtr hService, ref ServiceStatus status);

    protected override void OnStart(string[] args) {
        m_eventLog.WriteEntry(string.Format("{0} is starting.", ServiceName));
        m_serviceStatus = new ServiceStatus();
        m_serviceStatus.dwServiceType = ServiceType.SERVICE_WIN32_OWN_PROCESS;
        m_serviceStatus.dwCurrentState = ServiceState.SERVICE_START_PENDING;
        m_serviceStatus.dwWin32ExitCode = 0;
        m_serviceStatus.dwWaitHint = 2000;
        SetServiceStatus(this.ServiceHandle, ref m_serviceStatus);

        try {
            m_process = new Process();
            
            var startInfo = m_process.StartInfo;
            startInfo.UseShellExecute = false;
            startInfo.RedirectStandardOutput = true;
            startInfo.RedirectStandardError = true;
            startInfo.FileName = "$ServiceExe";
            startInfo.Arguments = "$ServiceArgs";
            $(if ($EnvironmentVariable) {
                $EnvironmentVariable.Keys |
                    ForEach-Object -Begin { $envSrc = '' } -Process {
                        $envSrc += @"
            startInfo.EnvironmentVariables["$_"] = "$($EnvironmentVariable[$_])";
"@
                    } -End {
                        $envSrc
                    }
                }
            )

            m_process.EnableRaisingEvents = true;
            m_process.OutputDataReceived += new DataReceivedEventHandler((s, e) => Console.WriteLine(e.Data));
            m_process.ErrorDataReceived += new DataReceivedEventHandler((s, e) => Console.WriteLine(e.Data));

            m_process.Exited += new EventHandler((s, e) => {
                Console.WriteLine("$ServiceExe exited unexpectedly ({0})",  m_process.ExitCode);
                if (m_writer != null) m_writer.Flush();
                m_serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
                SetServiceStatus(this.ServiceHandle, ref m_serviceStatus);
            });

            m_process.Start();
            m_process.BeginOutputReadLine();
            m_process.BeginErrorReadLine();
            m_serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
            Console.WriteLine("OnStart - Successfully started the service.");
            m_eventLog.WriteEntry(string.Format("{0} successfully started.", ServiceName));
        }
        catch (Exception e)
        {
            Console.WriteLine("OnStart - failed to start the service : {0}", e.Message);
            m_eventLog.WriteEntry(string.Format("{0} failed to start.\r\n{1}\r\n{2}", ServiceName, e.Message, e.Data), EventLogEntryType.Error);
            m_serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
        }
        finally {
            SetServiceStatus(this.ServiceHandle, ref m_serviceStatus);
            if (m_writer != null) m_writer.Flush();
        }
    }

    protected override void OnStop() {
        Console.WriteLine("OnStop {0}", ServiceName);
        m_eventLog.WriteEntry(string.Format("{0} is stopping.", ServiceName));
        try {
            m_serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
            if (m_process != null)
            {
                m_process.Kill();
                m_process.WaitForExit();
                m_process.Close();
                m_process.Dispose();
                m_process = null;
            }
            Console.WriteLine("OnStop - Sucessfully stopped the service {0}", ServiceName);
            m_eventLog.WriteEntry(string.Format("{0} was successfully stopped.", ServiceName));
        }
        catch (Exception e)
        {
            Console.WriteLine(string.Format("OnStop - Failed to stop the {0} service: {1}", ServiceName, e.Message));
            m_eventLog.WriteEntry(string.Format("{0} failed to stop.\r\n{1}\r\n{2}", ServiceName, e.Message, e.Data), EventLogEntryType.Error);
            m_serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;
        }
        finally {
            SetServiceStatus(this.ServiceHandle, ref m_serviceStatus);
            if (m_writer != null) m_writer.Flush();
        }
    }

    public static void Main() {
        System.ServiceProcess.ServiceBase.Run(new ${Name}ScmService());
    }
}
"@

    Add-Type -TypeDefinition $ServiceSrc -Language CSharp -OutputAssembly $WrappedServiceExe -OutputType ConsoleApplication -ReferencedAssemblies 'System.ServiceProcess' -ErrorAction Stop

    $WrappedServiceExe
}

<#
.SYNOPSIS

Creates a new SSH key for the current user.

.PARAMETER Destination

The path where the new SSH public/private key pair files should be stored.
By default, this is ~\.ssh\id_rsa.

.PARAMETER PassPhrase

The passphrase to use to protect the private key. This must be a minimum of 5 characters.
#>
function New-SshKey {
    Param (
        [Parameter(Position = 0)]
        [string] $Destination = "${env:USERPROFILE}\.ssh\id_rsa",

        [Parameter(Position = 1, ParameterSetName = 'PassPhrase')]
        [ValidateScript({ $_ -eq $null -or $_.Length -eq 0 -or $_.Length -ge 5 })]
        [string] $PassPhrase
    )

    Process {
        if ($null -ne $PassPhrase) {
            ssh-keygen.exe -N $PassPhrase -f $Destination
        } else {
            ssh-keygen.exe -f $Destination
        }
    }
}

function New-WindowsKubernetesClusterNode {
    [CmdletBinding()]
    Param (
        [string] $ConfigurationFile = $Script:KubernetesClusterNodeConfigurationPath,
        [string] $WorkspacePath = 'c:\k',
        [switch] $Force
    )

    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

    $Script:Cwd = Get-Location

    if (!(Test-Path $WorkspacePath)) {
        $null = New-Item -ItemType Directory -Path $WorkspacePath
    }

    try {
        Set-Location -Path $WorkspacePath

        $RequiresRestart = $False

        ######################################################################################################################
        #
        # Read Kubernetes cluster node configuration metadata
        #
        ######################################################################################################################
        if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
            $Script:Config = Get-KubernetesWindowsNodeConfiguration -Path $ConfigurationFile -ErrorAction Stop
            ValidateKubernetesWindowsNodeConfiguration -ErrorAction Stop
            if (!(Set-KubernetesWindowsNodeConfiguration $Script:KubernetesClusterNodeConfigurationPath -Force:$Force)) {
                $resp = Read-HostEx "Do you want to read the existing configuration file? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
                if (!$resp -or $resp -ieq 'y') {
                    $Script:Config = Get-KubernetesWindowsNodeConfiguration
                    ValidateKubernetesWindowsNodeConfiguration -ErrorAction Stop
                }
            }
        }
        
        if (!$Script:Config) {
            $Script:Config = Get-KubernetesWindowsNodeConfiguration
            ValidateKubernetesWindowsNodeConfiguration -ErrorAction Stop
        }
    
        if (!$Script:Config) {
            Write-Error "Unable to find existing kubernetes node configuration information at '$Script:KubernetesClusterNodeInstallationPath\.kubeclusterconfig'. Please supply a Kuberentes Cluster node configuration file."
        }
     
        Write-KubernetesWindowsNodeConfiguration $Script:Config

        ######################################################################################################################
        #
        # Configure Firewall
        #
        ######################################################################################################################
        if (Get-NetFirewallProfile -Name 'Domain','Private','Public' | ForEach-Object -Begin { $Enabled = $False } -Process { $Enabled = $Enabled -or $_.Enabled } -End { $Enabled }) {
            if (!($Force -and $Force.IsPresent)) {
                Write-Host "One or more of the Domain, Private, or Public firewall profiles are enabled."
                Write-Host "It is recommended to disable these firewall profiles."
                $resp = Read-HostEx -Prompt "Disable the Domain, Private, and Public firewall profiles? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
            }

            if (($Force -and $Force.IsPresent) -or !$resp -or $resp -ieq 'y') {
                Set-NetFirewallProfile -Name 'Domain','Private','Public' -Enabled False
                Write-Host "Disabled the Domain, Private and Public firewall profiles on this machine."
            }
        }

        ######################################################################################################################
        #
        # Uninstall Windows Defender
        #
        ######################################################################################################################
        $RequiresRestart = Uninstall-WindowsDefenderFeature -Force:$Force

        ######################################################################################################################
        #
        # Install Containers feature
        #
        ######################################################################################################################
        $RequiresRestart = $RequireRestart -or (Install-ContainersFeature -Force:$Force)

        ######################################################################################################################
        #
        # Remove existing SSH Capabilities; download newer SSH components and configure Ssh-Agent to start automatically and start SSH-Agent
        #
        ######################################################################################################################

        # The SSH-Agent that ships with Windows only supports sending RSA SHA-1 signatures. OpenSSH considers SHA-1 to be too
        # weak (given it only costs $50K to collide SHA-1 hashes). So newer versions of SSH reject these hashes. Which all but
        # makes the version of ssh-agent that ships with Windows useless when interacting with Linux servers. This has been
        # "fixed" for 18-months, but not yet released. Since we can't wait, let's just use the version the PowerShell team
        # maintains (which eventually ends up in Windows anyway).
        $OpenSshCapability = Get-WindowsCapability -Online | Where-Object { $_.Name -match 'OpenSSH' -and $_.State -eq 'Installed' }
        if ($OpenSshCapability) {
            $CapabilityRemovalResults = Remove-WindowsCapability -Name $OpenSshCapability.Name -Online:$($OpenSshCapability.Online)

            # Record whether or not the server requires a restart due to removing the OpenSSH capability.
            $RequiresRestart = $RequiresRestart -or $CapabilityRemovalResults.RestartNeeded
        }

        # Remove any existing mention of SSH in the PATH environment variable.
        if ($env:PATH -imatch [Regex]::Escape((Join-Path (Join-Path $env:SystemRoot System32) OpenSSH))) {
            $env:PATH = $env:PATH -replace [Regex]::Escape((Join-Path (Join-Path $env:SystemRoot System32) OpenSSH))
            [Environment]::SetEnvironmentVariable('PATH',$env:PATH,[EnvironmentVariableTarget]::Machine)
        }

        # Download and install the latest available version of OpenSSH as maintained by the PowerShell team.
        $LatestSSHReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/powershell/win32-openssh/releases/latest' |
            Where-Object { $_.prerelease -eq $False } |
            Select-Object -First 1
        $LatestSSHReleaseVersion = $LatestSSHReleaseMetadata.name -replace '^v(\d+\.\d+)\.\d+\.\d+(p\d+).*$','$1$2'

        Write-Host "Checking to see if SSH v$LatestSSHReleaseVersion is installed..."

        try {
            where.exe ssh.exe *>$null
            $SshIsInstalled = $?
            if ($SshIsInstalled) {
                Start-Process ssh "-V" -NoNewWindow -RedirectStandardError ssh.version -Wait
            }

            if (!$SshIsInstalled -or (Get-Content ssh.version) -notmatch $LatestSSHReleaseVersion) {
                $SshUrl = $LatestSSHReleaseMetadata.assets |
                    Where-Object { $_.name -ieq 'OpenSSH-Win64.zip' } |
                    Select-Object -ExpandProperty 'browser_download_url'
                Write-Host "Downloading SSH from '$SshUrl'..."
                DownloadAndExpandZipArchive -Url $SshUrl

                Move-Item -Path .\OpenSSH-Win64 -Destination C:\OpenSSH -Force
                $SshAgentPath = Join-Path (Join-Path C: OpenSSH) ssh-agent.exe
                $SshdPath = Join-Path (Join-Path C: OpenSSH) sshd.exe
                    
                # The below is from install-sshd.ps1 which is now in C:\OpenSSH. We don't need SSHD running,
                # we only want to replace ssh and ssh-agent (mainly ssh-agent). However, if SSHD is installed,
                # then replace it, too.
                $etwmanifest = 'C:\OpenSSH\openssh-events.man'
                $Sshd = Get-Service sshd -ErrorAction SilentlyContinue
                if ($Sshd)
                {
                    $sshd | Stop-Service
                    sc.exe delete sshd 1>$null
                }

                if (Get-Service ssh-agent -ErrorAction SilentlyContinue) {
                    Stop-Service ssh-agent
                    sc.exe delete ssh-agent 1>$null
                }

                # Unregister ETW provider
                wevtutil um `"$etwmanifest`"

                [xml]$xml = Get-Content $etwmanifest
                $xml.instrumentationManifest.instrumentation.events.provider.resourceFileName = 'C:\OpenSSH\ssh-agent.exe'
                $xml.instrumentationManifest.instrumentation.events.provider.messageFileName = 'C:\OpenSSH\ssh-agent.exe'

                $streamWriter = $null
                $xmlWriter = $null
                try {
                    $streamWriter = new-object System.IO.StreamWriter($etwmanifest)
                    $xmlWriter = [System.Xml.XmlWriter]::Create($streamWriter)    
                    $xml.Save($xmlWriter)
                }
                finally {
                    if($streamWriter) {
                        $streamWriter.Close()
                    }
                }

                #register etw provider
                wevtutil im `"$etwmanifest`"

                $sshAgentDesc = 'Agent to hold private keys used for public key authentication.'
                $null = New-Service -Name ssh-agent -DisplayName 'OpenSSH Authentication Agent' -Description $sshAgentDesc -BinaryPathName `"$sshagentpath`" -StartupType Automatic
                sc.exe sdset ssh-agent "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)"
                sc.exe privs ssh-agent SeImpersonatePrivilege

                if ($Sshd) {
                    $sshdDesc = 'SSH protocol based service to provide secure encrypted communications between two untrusted hosts over an insecure network.'
                    $null = New-Service -Name sshd -DisplayName "OpenSSH SSH Server" -BinaryPathName `"$sshdpath`" -Description $sshdDesc -StartupType Manual
                    sc.exe privs sshd SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege
                }

                # !!! END install-sshd.ps1

                # Add C:\OpenSSH to the front of the PATH, so that this version is picked up over the one installed with Windows.
                if ($env:PATH -inotmatch 'C:\\OpenSSH') {
                    $env:PATH = "C:\OpenSSH;$env:PATH"
                    [Environment]::SetEnvironmentVariable('PATH', $env:PATH, [EnvironmentVariableTarget]::Machine)
                }
            }
        } finally {
            Remove-Item ssh.version -ErrorAction SilentlyContinue
            Remove-Item -Recurse OpenSSH-Win64 -ErrorACtion SilentlyContinue
        }

        $SshAgent = Get-Service ssh-agent -ErrorAction SilentlyContinue
        if ($SshAgent) {
            $SshAgent | Set-Service -StartupType Automatic -PassThru | Start-Service
        }


        ######################################################################################################################
        #
        # If needed, register a resumption scheduled task and reboot the server.
        #
        ######################################################################################################################
        if ($RequiresRestart) {
            if (!($Force -and $Force.IsPresent)) {
                Write-Host "In order to continue configuring Kubernetes, the server must be restarted."
                $resp = Read-HostEx "Reboot the server now? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
                if (!$resp -or $resp -ieq 'y') {
                    try {
                        Register-KubernetesNodeInstallationResumptionScheduledTask

                        if ($Force -and $Force.IsPresent) {
                            Restart-Computer -Force:$Force
                            return
                        }
                    } catch {
                        Write-Error "An error occurred while scheduling the kubernetes node installation to resume at next logon."
                    }
                }
            }

            $MyModule = $MyInvocation.MyCommand.ModuleName
            $MyCommand = $MyInvocation.MyCommand.Name
            $MyArgs = $MyInvocation.Line -replace $MyInvocation.InvocationName
            Write-Host "The server must be restarted in order to continue configuring it as a kubernetes node."
            Write-Host "Once the server has restarted, log in and run the following commands:"
            Write-Host
            Write-Host "    Import-Module $MyModule"
            Write-Host "    $MyCommand $MyArgs"
            Write-Host

            return
        }


        ######################################################################################################################
        #
        # If a reboot was required, this cmdlet will reach here; Unregister the resumption scheduled task if one was created.
        #
        ######################################################################################################################
        $Task = Get-ScheduledTask -TaskName 'KubernetesNodeBootstrap' -ErrorAction SilentlyContinue
        if ($Task) {
            $Task | Unregister-ScheduledTask -Confirm:$False
            Write-Host 'Unregistered KubernetesNodeBootstrap scheduled task, as all prerequisite setup has been completed.'
        }


        # >>>>> TODO: Get rid of this??
        Get-HnsScriptModule -Path $Script:KubernetesClusterNodeInstallationPath
        $null = Import-Module "$Script:KubernetesClusterNodeInstallationPath\hns.psm1" -DisableNameChecking

        # >>>>> TODO: This should probably be moved into its own cmdlet (probably private cmdlet)
        ######################################################################################################################
        #
        # Setup SSH Key
        #
        ######################################################################################################################
        $SshKeyFile = Join-Path (Join-Path $env:USERPROFILE '.ssh') 'id_rsa'
        # If the current user's public SSH key is not detected...
        if (!(Test-Path $SshKeyFile)) {
            # If running interactively...
            if (!($Force -and $Force.IsPresent)) {
                $resp = Read-HostEx "Do you wish to generate a SSH Key and add it to the Linux control-plane node? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
                if (!$resp -or $resp -ieq 'y') {
                    Write-Host "Please follow the on-screen prompts to generate a SSH key and copy your public SSH key to the Linux control plane."
                    New-SshKey
                    @'
Host k8s-master
    AddKeysToAgent yes
    IdentitiesOnly yes
'@ | Set-Content -Path (Join-Path (Join-Path $env:USERPROFILE .ssh) config)

                    # Set the proper ACLs on the key file, or SSH won't let you copy it
                    icacls.exe $SshKeyFile /c /t /Inheritance:d
                    icacls.exe $SshKeyFile /c /t /Grant ${env:USERNAME}:F
                    icacls.exe $SshKeyFile /c /t /Remove Administrator "Authenticated Users" BUILTIN\Administrator BUILTIN Everyone System Users

                    # Add the key to the SSH Agent to enable passwordless, key-based authentication
                    Ssh-Add $SshKeyFile

                    # Copy the public key to the Linux Kubernetes control plane master
                    $CopySshKeyParams = @{
                        PublicSshKeyPath = "$SshKeyFile.pub"
                        RemoteUsername = $Script:Config.Kubernetes.ControlPlane.Username
                        RemoteHostname = $Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'
                    }
                    Copy-SshKey @CopySshKeyParams
                }
            } else <# Running unattended #> {
                $MachinePublicSshKeyPath = Join-Path (Join-Path $env:ALLUSERSPROFILE .ssh) id_rsa
                New-SshKey -Destination $MachinePublicSshKeyPath -PassPhrase ''
                Write-Host "Generated a machine SSH key."
                ssh-keyscan.exe "$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')" 2>$null | Out-File (Join-Path (Join-Path $env:USERPORFILE '.ssh') 'known_hosts')
                Write-Host "Added the Kubernetes master node as a SSH ""known host""."
                Write-Host

                Write-Warning @"

Before joining this server to the Kubernetes cluster, please execute one of the following commands on the Linux
Kubernetes master control-plane node '$($Config.Kubernetes.ControlPlane.Address -replace ':6443')' to add this Windows node's public key to the
"authorized keys file:

    echo $(Get-Content "${MachinePublicSshKeyPath}.pub" -Raw) >> ~/.ssh/authorized_keys"

Alternatively, execute the following command from another PowerShell shell on this machine to copy this Windows node's
public SSH key to the Linux Kubernetes master control plane:

    Copy-SshKey -PublicSshKeyPath $MachinePublicSshKeyPath.pub -RemoteUsername $($Script:Config.Kubernetes.ControlPlane.Username) -RemoteHostname $($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')

"@
            }
        } else <# The user's public SSH key was detected #> {
            # If running interacitevly..."
            if (!($Force -and $Force.IsPresent)) {
                Write-Host "A public SSH key file has been detected."
                Write-Host
                Write-Host "Your public SSH key can be used to connect to the Linux Kubernetes control plane in order to remotely configure it as"
                Write-Host "part of setting up this Windows Server as a Kubernetes worker node."
                Write-Host
                Write-host "If you do not copy your public SSH key to the Linux Kubernetes control plane, you will need to do so before joining"
                Write-Host "this server as a worker node to the Kubernetes cluster."
                Write-Host
                Write-Host "If you have already copied your public SSH key to the Linux Kubernetes contrtol plane, you can safely answer 'N' when"
                Write-Host "asked to copy your public SSH key."
                Write-Host
                $resp = Read-HostEx "Do you want to copy your public SSH key to the Linux Kubernetes control plane now? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
            } else <# running unattended #> {
                $resp = 'n'
            }
            
            $SshKeyFile = Join-Path (Join-Path $env:USERPROFILE .ssh) id_rsa
            if (!$resp -or $resp -ieq 'y') {
                Write-Host "Please follow the on-screen prompts to copy your public ssh key to the Linux Kubernetes master control plane."
                @'
Host k8s-master
    AddKeysToAgent yes
    IdentitiesOnly yes
'@ | Set-Content -Path (Join-Path (Join-Path $env:USERPROFILE .ssh) config)

                # Set the proper ACLs on the key file, or SSH won't let you copy it
                icacls.exe $SshKeyFile /c /t /Inheritance:d
                icacls.exe $SshKeyFile /c /t /Grant ${env:USERNAME}:F
                icacls.exe $SshKeyFile /c /t /Remove Administrator "Authenticated Users" BUILTIN\Administrator BUILTIN Everyone System Users

                # Add the key to the SSH Agent to enable passwordless, key-based authentication
                Ssh-Add $SshKeyFile

                # Copy the public key to the Linux Kubernetes control plane master
                $CopySshKeyParams = @{
                    PublicSshKeyPath = "$SshKeyFile.pub"
                    RemoteUsername = $Script:Config.Kubernetes.ControlPlane.Username
                    RemoteHostname = $Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'
                }
                Copy-SshKey @CopySshKeyParams
            } else {
                Write-Warning @"

Before joining this server to the Kubernetes cluster, please add your public SSH key to the Linux master control plane
node by executing the following command:

    @'
        Host k8s-master
            AddKeysToAgent yes
            IdentitiesOnly yes
    '@ | Set-Content -Path $SshKeyPath
    ssh-add $SshKeyPath
    Copy-SshKey -PublicSshKeyPath $SshKeyPath.pub -RemoteUsername $($Script:Config.Kubernetes.ControlPlane.Username) -RemoteHostname $($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')


"@
            }
        }

        ######################################################################################################################
        #
        # Install the Container Runtime Interface (CRI): one of dockerd or containerd
        #
        ######################################################################################################################
        Install-ContainerRuntimeInterface -Name $Script:Config.Cri.Name -Force:$Force

        ######################################################################################################################
        #
        # Get the required Kuberenetes binaries
        #
        ######################################################################################################################
        Get-KubernetesBinaries -Version $Script:Config.Kubernetes.Version -Force:$Force

        ######################################################################################################################
        #
        # Get the required Container Network Interface (CNI) binaries
        #
        ######################################################################################################################
        Get-CniBinaries -Version $Script:Config.Cni.Version -NetworkMode $Script:Config.Cni.NetworkMode -PluginName $Script:Config.Cni.Plugin.Name -PluginVersion $Script:Config.Cni.Plugin.Version -Force:$Force


        ######################################################################################################################
        #
        # Get Required Windows Server Docker Container Images
        #
        ######################################################################################################################
        Write-Host "Pulling required docker images. This could take a while..."
        @(
            $Script:Config.Images.NanoServer
            $Script:Config.Images.ServerCore
            $Script:Config.Images.Infrastructure.Pause
        ) | Get-DockerImage
        Write-Host "Docker images pulled."


        ######################################################################################################################
        #
        # Build any required custom infrastructure images and configure Windows networking for the Kubernetes cluster
        #
        ######################################################################################################################
        if (!$Script:Config.Images.Infrastructure.Build) {
            if (!($Force -and $Force.IsPresent)) {
                Write-Warning @"

If you haven't already configured Windows networking on the Kubernetes master control plane, please do so BEFORE joining this
server to the cluster.

Execute the following commands on the Linux Kubernetes master control plane:

    curl -L https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/kube-proxy.yml | sed 's/VERSION/v$($Script:Config.Kubernetes.Version)/g' | kubectl apply -f -
    kubectl apply -f https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/flannel-overlay.yml


"@
            } else {
                # If we don't need any custom infrastructure images, just configure the Kubernetes master control plane node for
                # Windows node networking using unmodified YAML configuration files
                @(
                    $Script:Config.Cni.Plugin.WindowsNodeConfigurationUrl,
                    $Script:Config.Kubernetes.KubeProxy.WindowsNodeConfigurationUrl
                ) | ForEach-Object {
                    $OutFile = Split-Path $_ -Leaf
                    Invoke-RestMethod -Method GET -Uri $_ -OutFile $OutFile

                    if ($OutFile -imatch 'kube-proxy') {
                        (Get-Content $OutFile -Raw) -replace '(image: sigwindowstools/kube-proxy:)VERSION$',"`${1}v$($Script:Config.Kubernetes.Version)" |
                            Set-Content $OutFile
                    }

                    if ((Test-Path $env:USERPROFILE\.ssh\id_rsa) -and (ssh-agent -L) -match "(?m)\s+$($env:USERPROFILE -replace '\\','\\')\\\.ssh\\id_rsa$") {
                        $resp = Read-HostEx @"
If your SSH key has been copied to and authorized on the Linux Kubernetes master control plane node, do yo uwant to
copy Kubernetes configuration files to the master node and configure the Kubernetes cluster in order to join this
server to the cluster as a worker node? [Y|n] (Default 'Y') 
"@
                        if (!$resp -or $resp -ieq 'y') {
                            scp -o StrictHostKeyChecking=no $OutFile "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'):~/$OutFile"
                            ssh -T "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')" kubectl apply -f $OutFile
                        } else {
                            Write-Warning @"
Before you can run Join-KubernetesCluster on this node, you must perform the following commands to configure the
cluster to run this server as a worker node:

    scp -o StrictHostKeyChecking=no flannel-overlay.yml "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'):~/flannel-overlay.yml"
    scp -o StrictHostKeyChecking=no kube-proxy.yml "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'):~/kube-proxy.yml"
    ssh -T "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')" kubectl apply -f flannel-overlay.yml
    ssh -T "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')" kubectl apply -f kube-proxy.yml

"@
                        }
                    }
                }
            }
        } else {
            # Otherwise, build custom networking container images and modify the YAML configuration files to use these
            # custom docker container images when the node is joined to the cluster.
            Write-Host "The detected version of windows is v$Script:WinVer."
            Write-Host
            Write-Host "To setup this computer as a Kubernetes cluster node, custom docker container images are required because the current"
            Write-Host "version of Windows is not one of Windows Server LTSC2019 (1809), 1903, or 1909."
            Write-Host
            Write-Host "Docker on Windows requires that Windows-based Docker container images' base Windows operating system must match the host"
            Write-Host "operating system. Otherwise, the container will not start."
            
            New-KubernetesPauseContainerImage $Script:Config.Images.Infrastructure.PauseDockerfile -Force:$Force -ErrorAction Stop
            Write-Host "Built custom Kubernetes infrastructure container image 'kubeletwin/pause'."

            $GoLangVersionMetadata = Get-GoLangVersionMetadata

            New-GoLangContainerImage -GoLangVersionMetadata $GoLangVersionMetadata -Force:$Force -ErrorAction Stop
            Write-Host "Built custom Golang docker container image."

            if ($Script:Config.Cni.Plugin.Name -eq 'flannel') {
                $FlannelContainerImageParams = @{
                    GoLangDockerImageTag = "$($goLangVersionMetadata.Version)-windowsservercore-$Script:WinVer"
                    FlannelDockerfile = $Script:Config.Images.Infrastructure.FlannelDockerfile
                    FlannelVersion = $Script:Config.Cni.Plugin.Version
                    CniVersion = $Script:Config.Cni.Version
                    Force = $Force
                }
                New-KubernetesFlannelContainerImage -ErrorAction Stop @FlannelContainerImageParams
                Write-Host "Built custom Kubernetes Windows flannel docker container networking image."
            }

            New-KubernetesKubeProxyContainerImage -KubeProxyDockerfile $Script:Config.Images.Infrastructure.KubeProxyDockerfile -KubernetesVersion $Script:Config.Kubernetes.Version -Force:$Force -ErrorAction Stop
            Write-Host "Built custom Kubernetes kube-proxy docker container image."

            @(
                $Script:Config.Cni.Plugin.WindowsNodeConfigurationUrl,
                $Script:Config.Kubernetes.KubeProxy.WindowsNodeConfigurationUrl
            ) | ForEach-Object {
                $ConfigurationUrl = $_
                $Outfile = Split-Path $_ -Leaf

                switch ($Outfile) {
                    'flannel-overlay.yml' {
                        (Invoke-RestMethod -Method GET -Uri $ConfigurationUrl) `
                            -replace '(?m)sigwindowstools/flannel:\d+\.\d+\.\d+$', @"
kubeletwin/flannel:$($Script:Config.Cni.Plugin.Version)-windowsservercore-$Script:WinVer
        imagePullPolicy: Never
"@ |
                            Set-Content $Outfile
                        break;
                    }
                    'kube-proxy.yml' {
                        (Invoke-RestMethod -Method GET -Uri $ConfigurationUrl) `
                            -replace '(?m)sigwindowstools/kube-proxy:VERSION$', @"
kubeletwin/kube-proxy:$($Script:Config.Kubernetes.Version)-windowsservercore-$Script:WinVer
        imagePullPolicy: Never
"@ |
                            Set-Content $Outfile
                        break;
                    }

                    default {
                        Invoke-RestMethod -Method GET -Uri $ConfigurationUrl -OutFile $OutFile
                        break;
                    }
                }

                if (!($Force -and $Force.IsPresent)) {
                    scp -o StrictHostKeyCHecking=no $OutFile "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'):~/$OutFile"
                    ssh -T "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')" kubectl apply -f $OutFile
                }
            }

            if ($Force -and $Force.IsPresent) {
                Write-Warning @"

If you haven't already configured Windows networking on the Kubernetes master control plane, please do so BEFORE joining this
server to the cluster.

Execute the following commands from this server against the Linux Kubernetes master control plane:

    $(
        @(
            Split-Path $Script:Config.Cni.Plugin.WindowsNodeConfigurationUrl -Leaf
            Split-Path $Script:Config.Kubernetes.KubeProxy.WindowsNodeConfigurationUrl -Leaf
        ) | ForEach-Object {
            "    scp -o StrictHostKeyChecking=no $(Join-Path $PWD $_) `"$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'):~/$_`"`n"
            "    ssh -T `"$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443')`" kubectl apply -f $_"
        }
    )


"@
            }
        }

        ######################################################################################################################
        #
        # Create Docker NAT network 'host' and set scheduled task to recreate the network on restarts of the server
        #
        ######################################################################################################################
        if (!(docker network ls -f name=host -q)) {
            docker network create -d nat host

            if (!(docker network ls -f name=host -q)) {
                Write-Error 'Failed to create Docker NAT network ''host''.'
            }
        }

        if (!(Get-ScheduledTask -TaskName 'Create Docker NAT network ''host''' -ErrorAction SilentlyContinue)) {
            # Windows does not persist "custom" Docker NAT networks between server restarts. But Kubernetes requires
            # this network to exist. So register a scheduled task that ensures this network is created on restarts.
            Register-DockerHostNetworkCreationScheduleTask
        }
        
        if (!($Force -and $Force.IsPresent)) {
            $resp = Read-HostEx "`nnWould you like to join this server to the Kubernetes cluster now? [y/N] (Default 'N') " -ExpectedValue 'y','N'
            if ($resp -ieq 'Y') {
                Join-KubernetesCluster
            }
        } else {
            Write-Host 'When you''re ready to join this server to the Kubernetes cluster, plesee execute the following commands:'
            Write-Host
            Write-Host '    Import-Module WindowsKubernetesWorkerNode'
            Write-Host '    Join-KubernetesCluster'
            Write-Host
        }
    } finally {
        Set-Location $Script:Cwd
    }
}

function Read-HostEx {
    Param (
        [string] $Prompt,
        [string[]] $ExpectedValue,
        [switch] $ValueRequired
    )

    $Response = '$$INVALID$$'
    do {
        $Response = Read-Host -Prompt $Prompt
        if (!$Response -and $ValueRequired -and $ValueRequired.IsPresent) {
            Write-Host 'A response is required. Please try again.'
        } elseif ($Response -and $Response -inotin $ExpectedValue) {
            Write-Host 'Invalid response. Please try again.'
        }
    } while ((!$Response -and $ValueRequired -and $ValueRequired.IsPresent) -or ($Response -and $Response -inotin $ExpectedValue))

    $Response
}

<#
.SYNOPSIS
    Sets up a scheduled task to run when the server starts up to create a Docker NAT network named 'host'.

.DESCRIPTION

    Windows is lame in that custom NAT networks which are created, particularly for Docker, are not
    persisted between reboots. When setting up a Kubernetes cluster, an address space is provided froh which
    Pods and containers are given IP addresses, usually as part of a NAT network. The default Docker NAT
    network 'nat' could be modified, but I haven't found how to do that. 

    Instead, this cmdlet will setup a scheduled task to ensure the Docker 'host' NAT network is created
    once docker is running.

#>
function Register-DockerHostNetworkCreationScheduleTask {
    $Command = '{ $DockerSvc = Get-Service docker; while ($DockerSvc.Status -ne ''Running'') { Write-Info ''Waiting for docker to start...''; Start-Sleep -Seconds 1; $DockerSvc.Refresh(); }; if (!(docker network ls -f name=host -q)) { docker network create -d nat host }; if (!(docker network ls -f name=host -q)) { Write-Error ''Failed to create ''''host'''' Docker NAT network!'' } else { Write-Information ''Successfully created ''''host'''' Docker NAT network.'' }; }'
    $Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -Command {0}' -f $Command)
    $Trigger = New-ScheduledTaskTrigger -AtStartup
    $null = Register-ScheduledTask -TaskName 'Create Docker NAT network ''host''' -Description 'Upon startup, once Docker is running, creates a Docker NAT network named ''host''. Windows does not persist custom Docker NAT networks between reboots.' -Action $Action -Trigger $Trigger -RunLevel Highest
}

function Register-KubernetesNodeInstallationResumptionScheduledTask {
    $MyArgs = $MyInvocation.Line -replace $MyInvocation.InvocationName
    $MyCommand = $MyInvocation.MyCommand.Name
    $MyModule = $MyInvocation.MyCommand.ModuleName

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass { Import-Module '$MyModule'; $MyCommand $MyArgs }" -WorkingDirectory $pwd
    Write-Output "Created scheduled task action to resume kubernetes node installation after reboot."

    try {
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        Write-Output "Cretaed a scheduled task trigger to execute the task action at the next logon."

        $null = Register-ScheduledTask -TaskName "KubernetesNodeBootstrap" -Action $action -Trigger $trigger -RunLevel Highest
        Write-Host "Registered the scheduled task."
    } catch {
        throw
    }
}

function Remove-Containers { docker ps -aq | ForEach-Object { docker rm $_ -f } }

function Remove-KubernetesBinaries {
    Param (
        [Parameter(Position = 0)]
        [string] $Path = $Script:KubernetesClusterNodeInstallationPath
    )

    Remove-Item env:\KUBECONFIG -ErrorAction SilentlyContinue

    [EnvironmentVariableTarget].GetEnumNames() | ForEach-Object {
        $existingPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::$_)
        $existingPath = $existingPath -replace "$Path\\bin;"
        [Environment]::SetEnvironmentVariable("PATH", $existingPath, [EnvironmentVariableTarget]::$_)
    }

    Remove-Item $Path -Recurse -Force -ErrorACtion SilentlyContinue
}

function Remove-KubernetesNetwork {
    Param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [string] $NetworkName = 'vxlan0'
    )

    Process {
        $HnsNetwork = Get-HnsNetwork | Where-Object { $_.Name -eq $NetworkName.ToLower() }

        if ($HnsNetwork)
        {
            Write-Host "Removing existing HNS network:"
            Write-Host ($HnsNetwork | ConvertTo-Json -Depth 10) 
            Remove-HnsNetwork $HnsNetwork
        }
    }
}

function Remove-WindowsKubernetesClusterNode {
    Param (
        [Parameter(Position = 0)]
        [string] $KubernetesClusterNodeInstallationPath = $Script:KubernetesClusterNodeInstallationPath,
        
        [Parameter(Position = 1)]
        [string] $KubernetesClusterNodeConfigurationPath = $Script:KubernetesClusterNodeConfigurationPath,

        [switch] $RemoveDockerContainers,

        [switch] $Force
    )

    $Script:Config = Get-KubernetesClusterNodeConfiguration -Path $KubernetesClusterNodeConfigurationPath
    kubectl.exe delete node $env:COMPUTERNAME.ToLower()

    if ($RemoveDockerContainers -and $RemoveDockerContainers.IsPresent) {
        Remove-Containers
    }

    Uninstall-ContainerNetworkInterface -PluginName $Script:Config.Cni.Plugin.Name
    Uninstall-KubeProxy
    Uninstall-Kubelet
    Remove-KubernetesBinaries -Path $KubernetesClusterNodeInstallationPath
    Remove-KubernetesNetwork -NetworkName $Script:Config.Cni.NetworkName

    Remove-Item $KubernetesClusterNodeInstallationPath -Recurse -ErrorAction SilentlyContinue -Force:$Force
    Remove-Item $env:USERPROFILE\.kube -Recurse -ErrorAction SilentlyContinue -Force:$Force
}

function Set-CniConfiguration {
    Param (
        [string] $Path = $Script:CniConfigurationPath,

        [string] $CriName = 'dockerd',

        [string] $NodeIpAddress = (Get-InterfaceIpAddress),

        [string] $NodeSubnet = (Get-InterfaceSubnet),

        [ValidateSet('flannel','kubenet')]
        [string] $PluginName = 'flannel',

        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay',

        [string] $NetworkName = 'vxlan0',

        [string] $ClusterCIDR = '10.244.0.0/16',

        [string] $ServiceCIDR = '10.96.0.0/12'
    )

    Process {
        $NetworkMode = $NetworkMode.ToLower()
        $NetworkName = $NetworkName.ToLower()

        if ($NetworkMode -ieq 'l2bridge') {
            $CniConfig = ConvertFrom-JSON '{
    "cniVersion": "0.2.0",
    "name": "<NetworkName>",
    "type": "flannel",
    "capabilities": {
        "dns": true
    },
    "delegate": {
        "type": "win-bridge",
        "policies": [
            {
                "Name": "EndpointPolicy",
                "Value": {
                    "Type": "OutBoundNAT",
                    "ExceptionList": [
                        "<ClusterCIDR>",
                        "<ServiceCIDR>",
                        "<MgmtSubnet>"
                    ]
                }
            },
            {
                "Name": "EndpointPolicy",
                "Value": {
                    "Type": "ROUTE",
                    "DestinationPrefix": "<ServerCIDR>",
                    "NeedEncap": true
                }
            },
            {
                "Name": "EndpointPolicy",
                "Value": {
                    "Type": "ROUTE",
                    "DestinationPrefix": "<MgmtSubnet>",
                    "NeedEncap": true
                }
            }
        ]
    }
}
'
            $CniConfig.name = $NetworkName
            $CniConfig.type = $PluginName
            $OutboundNatExceptions = $CniConfig.delegate.policies[0].Value.ExceptionList
            $OutboundNatExceptions[0] = $ClusterCIDR
            $OutboundNatExceptions[1] = $ServiceCIDR
            $OutboundNatExceptions[2] = $NodeSubnet

            if ($CriName -ieq 'dockerd') {
                $CniConfig.delegate.policies[1].Value.DestinationPrefix = $ServiceCIDR
                $CniConfig.delegate.policies[2].Value.DestinationPrefix = "${NodeIPAddress}/32"
            } else {
                $CniConfig.capabilities = $CniConfig.capabilities | Add-Member -MemberType NoteProperty -Name 'portMappings' -Value $true -PassThru
                $CniConfig.delegate.type = 'sdnbridge'

                $PolicyValue = $CniConfig.delegate.policies[0].Value
                $Exceptions = $PolicyValue.ExceptionList
                $PolicyValue.PSObject.Properties.Remove('ExceptionList')
                $PolicyValue = $PolicyValue | Add-Member -MemberType NoteProperty -Name 'Settings' -Value @{ Exceptions = $Exceptions }
                
                $PolicyValue = $CniConfig.delegate.policies[1].Value
                $PolicyValue.Type = 'SDNROUTE'
                'DestinationPrefix','NeedEncap' | ForEach-Object { $PolicyValue.PSObject.Properties.Remove($_) }
                $PolicyValue = $PolicyValue | Add-Member -MemberType NoteProperty -Name 'Settings' -Value @{ DestinationPrefix = $ServiceCIDR; NeedEncap = $True } -PassThru

                $PolicyValue = $CniConfig.delegate.policies[2].Value
                $PolicyValue.Type = 'SDNROUTE'
                'DestinationPrefix','NeedEncap' | ForEach-Object { $PolicyValue.PSObject.Properties.Remove($_) }
                $PolicyValue = $PolicyValue | Add-Member -MemberType NoteProperty -Name 'Settings' -Value @{ DestinationPrefix = "${NodeIPAddress}/32"; NeedEncap = $True } -PassThru

                $Policies = $CniConfig.delegate.policies
                $CniConfig.delegate.PSObject.Properties.Remove('policies')
                $CniConfig.delegate = $CniConfig.delegate | Add-Member -MembxerType NoteProperty -Name 'AdditionalArgs' -Value $Policies -PassThru
            }
        } else {
            $CniConfig = ConvertFrom-JSON '{
    "cniVersion": "0.2.0",
    "name": "<NetworkName>",
    "type": "flannel",
    "capabilities": {
        "dns": true
    },
    "delegate": {
        "type": "win-overlay",
        "policies": [
            {
                "Name": "EndpointPolicy",
                "Value": {
                    "Type": "OutBoundNAT",
                    "ExceptionList": [
                        "<ClusterCIDR>",
                        "<ServiceCIDR>"
                    ]
                }
            },
            {
                "Name": "EndpointPolicy",
                "Value": {
                    "Type": "ROUTE",
                    "DestinationPrefix": "<ServiceCIDR>",
                    "NeedEncap": true
                }
            }
        ]
    }
}
'
            $CniConfig.name = $NetworkName
        
            $OutboundNatExceptions = $CniConfig.delegate.policies[0].Value.ExceptionList
            $OutboundNatExceptions[0] = $ClusterCIDR
            $OutboundNatExceptions[1] = $ServiceCIDR

            if ($CriName -ieq 'dockerd') {
                $CniConfig.delegate.policies[1].Value.DestinationPrefix = $ServiceCIDR
            } else {
                Write-Error "SHOULDN'T BE HERE!!!"
                $CniConfig.capabilities = $CniConfig.capabilities | Add-Member -MemberType NoteProperty -Name 'portMappings' -Value $True -PassThru
                $CniConfig.delegate.type = 'sdnoverlay'

                $PolicyValue = $CniConfig.delegate.policies[0].Value
                $Exceptions = $PolicyValue.ExceptionList
                $PolicyValue.PSObject.Properties.Remove('ExceptionList')
                $PolicyValue = $PolicyValue | Add-Member -MemberType NoteProperty -Name 'Settings' -Value @{ Exceptions = $Exceptions }

                $PolicyValue = $CniConfig.delegate.policies[1].Value
                $PolicyValue.Type = 'SDNROUTE'
                'DestinationPrefix','NeedEncap' | ForEach-OBject { $PolicyValue.PSObject.Properties.Remove($_) }
                $PolicyValue = $PolicyValue | Add-Member -MemberType NoteProperty -Name 'Settings' -Value @{ DestinationPrefix = "$ServiceCIDR"; NeedEncap = $True }

                $Policies = $CniConfig.delegate.policies
                $CniConfig.delegate.PSObject.Properties.Remove('policies')
                $CniConfig.delegate = $CniConfig.delegate | Add-Member -MemberType NoteProperty -Name 'AdditionalArgs' -Value $Policies -PassThru
            }
        }

        $Folder = Split-Path $Path -Parent
        if (!(Test-Path $Folder)) {
            $null = New-Item -ItemType Directory $Folder
        }

        $CniConfigJson = ConvertTo-JSON $CniConfig -Depth 100
        
        Set-Content -Path $Path -Value $CniConfigJson -Force
        
        Write-Host "Generated CNI configuration:`r`n`r`n$CniConfigJson`r`n`r`n"
    }
}

function Set-KubernetesWindowsNodeConfiguration {
    [CmdletBinding()]
    [OutputType([Boolean])]
    Param (
        [Parameter(Position = 0)]
        [string] $Path = (Join-Path (Join-Path $env:ALLUSERSPROFILE 'Kubernetes') '.kubewindowsnodeconfig'),

        [Parameter(ValueFromPipeline)]
        [PSTypeName('KubernetesWindowsNodeConfiguration')]
        [PSCustomObject] $Config = $Script:Config,

        [switch] $Force
    )

    Process {
        if ((Test-Path $Path) -and !($Force -and $Force.IsPresent)) {
            Write-Host "A kubernetes cluster node configuration file already exists at '$Path'."
            $res = Read-Host -Prompt "Do you want to overwrite it? [N/y] (Default 'N') "
            if ($res -ine 'Y') {
                $False
                return
            }
        }

        if ($Path -ne $Script:KubernetesClusterNodeConfigurationPath) {
            $Script:KubernetesClusterNodeConfigurationPath = $Path
        }

        $Folder = Split-Path $Path -Parent
        if (!(Test-Path $Folder)) {
            $null = New-Item -ItemType Directory -Path $Folder -Force -ErrorAction Stop
        }

        Set-Content -Path $Path -Value ($Config | ConvertTo-JSON -Depth 100) -Encoding UTF8 -Force
        $True
    }
}

function Set-NetConfig {
    Param (
        [string] $Path = $Script:NetworkConfigurationPath,

        [string] $ClusterCIDR = '10.244.0.0/16',

        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay',

        [string] $NetworkName = 'vxlan0'
    )

    Process {
        $NetworkMode = $NetworkMode.ToLower()
        $NetworkName = $NetworkName.ToLower()

        $NetConfig = ConvertFrom-Json '{
  "Network": "10.244.0.0/16",
  "Backend": {
    "name": "cbr0",
    "type": "host-gw"
  }
}
'
        $NetConfig.Network = $ClusterCIDR
        $NetConfig.Backend.name = $NetworkName

        if ($NetworkMode -eq 'overlay') {
            $NetConfig.Backend.type = 'vxlan'
        }

        $NetConfigJson = ConvertTo-JSON $NetConfig -Depth 100

        Set-Content -Path $Path -Value $NetConfigJson
        
        Write-Host "Generated net-conf Config:`r`n`r`n$NetConfigJson`r`n`r`n"
    }
}

function Test-NodeRunning {
    kubectl.exe get nodes/$($env:COMPUTERNAME.ToLower())
    return !$LASTEXITCODE
}

function Uninstall-ContainerNetworkInterface {
    Param (
        [Parameter(Position = 0)]
        [ValidateSet('flannel','kubenet')]
        [string] $PluginName = 'flannel',

        [Parameter(Position = 1)]
        [string] $PluginInstallationPath = 'c:\flannel'
    )

    switch ($PluginName) {
        'kubenet' { break }
        'flannel' {
            Uninstall-Flanneld -InstallPath $PluginInstallationPath
            break;
        }
    }
}

function Uninstall-WindowsDefenderFeature {
    [OutputType([Boolean])]
    Param ( [switch] $Force )

    if ((Get-WindowsFeature -Name 'Windows-Defender').Installed) {
        if (!($Force -and $Force.IsPresent)) {
            Write-Host "The Windows Defender feature is installed on this machine. It is recommended to uninstall it."
            Write-Host "Uninstalling Windows Defender will require this machine to be restarted before the Kubernetes node can be configured."

            $resp = Read-HostEx -Prompt "Uninstall Windows Defender? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
        }

        if (($Force -and $Force.IsPresent) -or !$resp -or $resp -ieq 'y') {
            Uninstall-WindowsFeature -Name 'Windows-Defender'
            Write-Host "The Windows Defender feature has been uninstalled from this machine."
            $True
        }
    } else {
        $False
    }
}

function Uninstall-Flanneld {
    Param (
        [Parameter(Position = 0)]
        $InstallPath = 'C:\flannel'
    )

    $FlannelSvc = Get-Service 'Flanneld'
    if ($FlannelSvc) {
        $FlannelSvc | Remove-Service
        Write-Host "Uninstalled the $($FlannelSvc.Name) service."
    }

    if (Test-Path $InstallPath) {
        Remove-Item $InstallPath -Force -Recurse -ErrorAction SilentlyContinue
        Write-Host "Removed flanneld."
    }
}

function Uninstall-Kubelet {
    Write-Host "Uninstalling Kubelet Service"
    # close firewall for 10250
    $FirewallRule = (Get-NetFirewallRule -Name KubeletAllow10250 -ErrorAction SilentlyContinue )
    if ($FirewallRule)
    {
        Remove-NetFirewallRule $FirewallRule
    }

    $KubeletSvc = Get-Service Kubelet
    if ($KubeletSvc) {
        Remove-Service -ServiceName Kubelet
        Write-Host 'Uninstalled the Kubelet service.'
    }
     
    & cmd /c kubeadm reset -f '2>&1'
    Write-Host 'Removed this node from the kubernetes cluster.'
}

function Uninstall-KubeProxy {
    $Service = Get-Service 'kubeproxy'
    if ($Service) {
        $Service | Remove-Service
        Write-Host 'Uninstalled the KubeProxy service.'
    }
}

function Write-KubernetesWindowsNodeConfiguration {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [PSTypeName('KubernetesWindowsNodeConfiguration')]
        [PSCustomObject] $Config = $Script:Config
    )

    Write-Host @"
########################################################################################################################

This is the Kubernetes Cluster Node Configuration data which will be used to configure this node:

    Container Runtime Interface: $($Config.Cri.Name)
    Container Network Interface:
        Mode:    $($Config.Cni.NetworkMode)
        Name:    $($Config.Cni.NetworkName)
        Version: $($Config.Cni.Version)
        Plugin:  $($Config.Cni.Plugin.Name) v$($Config.Cni.Plugin.Version)
    Kubernetes:
        Version: v$($Config.Kubernetes.Version)
        Control Plane Information:
            Master Node Address: $($Config.Kubernetes.ControlPlane.Address)
            Username:            $($Config.Kubernetes.ControlPlane.Username[0])$("*" * 8)$($Config.Kubernetes.ControlPlane.Username[-1])
            Join Token:          $("*" * ($Config.Kubernetes.ControlPlane.JoinToken.Length - 4))$($Config.Kubernetes.ControlPlane.JoinToken.Substring($Config.Kubernetes.ControlPlane.JoinToken.Length - 4))
            CA Hash:             $("*" * ($Config.Kubernetes.ControlPlane.CAHash.Length - 8))$($Config.Kubernetes.ControlPlane.CAHash.Substring($Config.Kubernetes.ControlPlane.CAHash.Length - 8))
        Network Information:
            Cluster CIDR:           $($Config.Kubernetes.Network.ClusterCIDR)
            Service CIDR:           $($Config.Kubernetes.Network.ServiceCIDR)
            DNS Service IP Address: $($Config.Kubernetes.Network.DnsService.IPAddress)
    Node Interface Information:
        Name:            $($Config.Node.InterfaceName)
        IP Address:      $($Config.Node.IPAddress)
        Subnet:          $($Config.Node.Subnet)
        Default Gateway: $($Config.Node.DefaultGateway)
    Docker Images:
        Nano Server Image: $($Config.Images.NanoServer)
        Server Core Image: $($Config.Images.ServerCore)
        Infrastructure Images:
            Build? $(if ($Config.Images.Infrastructure.Build) { '                Yes' } else  { 'No' })
$(if ($Config.Images.Infrastructure.Build) {
    "            Flannel Dockerfile:    $($Config.Images.Infrastructure.FlannelDockerfile)`n"
    "           Kube-Proxy Dockerfile: $($Config.Images.Infrastructure.KubePRoxyDockerfile)`n"
    "           Pause Dockerfile:      $($Config.Images.Infrastructure.PauseDockerfile)"
} else {
    "            Pause: $($Config.Images.Infrastructure.Pause)"
})
    Wins:
        Version: $($Config.Wins.Version)

########################################################################################################################

"@
}

[PSTypeName('KubernetesWindowsNodeConfiguration')]
[PsCustomObject] $Script:Config = [PSCustomObject] $null

[string] $Script:Cwd = Get-Location
[string] $Script:WinVer = Get-WindowsBuildVersion
[string] $Script:KubernetesClusterNodeInstallationPath = Join-Path $env:ALLUSERSPROFILE 'Kubernetes'
[string] $Script:KubernetesClusterNodeConfigurationPath = Join-Path $KubernetesClusterNodeInstallationPath '.kubewindowsnodeconfig'
[string] $Script:KubernetesClusterNodeLogPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'logs'
[string] $Script:CniPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'cni'
[string] $Script:CniConfigurationPath = Join-Path (Join-Path $Script:CniPath 'config') 'cni.conf'
[string] $Script:NetworkConfigurationPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'net-conf.json'
[string] $Script:WinsPath = Join-Path C: wins

$ProgressPreference = 'SilentlyContinue'