[PSTypeName('KubernetesNodeInstallationConfiguration')]
[PsCustomObject] $Script:Config

[string] $Script:KubernetesClusterNodeInstallationPath = Join-Path $env:ALLUSERSPROFILE 'Kubernetes'
[string] $Script:KubernetesClusterNodeConfigurationPath = Join-Path $KubernetesClusterNodeInstallationPath '.kubeclusternodeconfig'
[string] $Script:KubernetesClusterNodeLogPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'logs'
[string] $Script:CniPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'cni'
[string] $Script:CniConfigurationPath = Join-Path (Join-Path $Script:CniPath 'config') 'cni.conf'
[string] $Script:CniNetworkConfigurationPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'net-conf.json'

$ProgressPreference = 'SilentlyContinue'

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
        [Praameter(Position = 1)]
        [string] $DestinationPath = '.'
    )

    Process {
        try {
            $ZipFile = New-TemporaryFile
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
        [Parameter(Position = 1, Mandatory)]
        [string] $Destination,
        [switch] $Force
    )

    Process {
        if (!($Force -and $Force.IsPresent) -and (Test-Path $Destination)) {
            Write-Host "[DownloadFile] File '$Destination' already exists."
            return
        }

        $InsecureProtocols = @([Net.SecurityProtocolType]::SystemDefault, [Net.SecurityProtocolType]::Ssl3)
        [Net.ServicePointManager]::SecurityProtocol = @(foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType])) {
            if ($protocol -notin $InsecureProtocols) {
                $protocol
            }
        })

        try {
            Invoke-RestMethod -Method GET -Uri $Url -OutFile $Destination
            Write-Host "Downloaded [$Url] => [$Destination]"
        } catch {
            Write-Error "Failed to download '$Url'"
            throw
        }
    }
}

function ValidateKubernetesClusterNodeConfiguration {
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

            $WinVer = "$([Environment]::OSVersion.Version)"
            if (!$Script:Config.Images) {
                $Script:Config | Add-Configuration 'Images' ([PSCustomObject]@{
                    NanoServer = "mcr.microsoft.com/windows/nanoserver:$WinVer"
                    ServerCore = "mcr.microsoft.com/windows/servercore:$WinVer"
                    Pause = [PSCustomObject]@{
                        BuildImage = $True
                        Dockerfile = 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'
                        Image = ''
                    }
                })

                Write-Host 'An ''Images'' section cannot be found. Using the following images:'
                Write-Host "    Windows Nano Server: $($Script:Config.Images.NanoServer)"
                Write-Host "    Windows Server Core: $($Script:Config.Images.ServerCore)"
                Write-Host "    Pause infrastructure image: Will be built from the dockerfile located at '$($Script:Config.Images.Pause.Dockerfile)'."
            }

            if (!$Script:Config.Images.NanoServer) {
                $Script:Config.Images | Add-Configuration 'NanoServer' "mcr.microsoft.com/windows/nanoserver:$WinVer"
                Write-Host "'Images.NanoServer' was not specified. Using '$($Script:Config.Images.NanoServer)'."
            }

            if (!$Script:Config.Images.ServerCore) {
                $Script:Config.Images | Add-Configuration 'ServerCore' "mcr.microsoft.com/windows/servercore:$WinVer"
                Write-Host "'Images.ServerCore' was not specified. Using '$($Script:Config.Images.ServerCore)'."
            }

            if (!$Script:Config.Images.Pause) {
                $Script:Config.Images | Add-Configuration 'Pause' ([PSCustomObject]@{
                    Build = $True
                    Dockerfile = 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'
                    Image = ''
                })
                Write-Host "'Images.Pause' was not specified. An image will be built from the dockerfile located at '$($Script:Config.Images.Pause.Dockerfile)'."
            }


            if ($Script:Config.Images.Pause.Build -and !$Script:Config.Images.Pause.DockerFile) {
                $Script:Config.Images.Pause | Add-Configuration 'Dockerfile' 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'
                Write-Host "'Images.Pause.Build' was specified but 'Images.Pause.Dockerfile' was not."
                Write-Host "An image will be built from the dockerfile located at '$($Script:Config.Images.Pause.Dockerfile)'."
            } elseif (!($Script:Config.Images.Pause.Build -or $Script:Config.Images.Pause.Image)) {
                $Script:Config.Images.Pause | Add-Configuration 'Image' 'mcr.microsoft.com/oss/kubernetes/pause:1.3.0'
                Write-Host "'Images.Pause.Build' was not specified or set to 'False', but no 'Images.Pause.Image' was specified."
                Write-Host "Using '$($Script:Config.Images.Pause.Image)'."
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
        Get-Content $PublicSshKeyPath | ssh "${RemoteUsername}@${RemoteHostname}$(if ($Port) { ":$Port" })" "cat >> .ssh/authorized_keys"
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
        [string] $PluginVersion = '0.13.0'
    )

    Process {
        $Script:CniPath = $Path
        $Script:CniConfigurationPath = (Join-Path $Script:CniPath 'config')

        if (!(Test-Path $Script:CniConfigurationPath)) {
            $null = New-Item -ItemType Directory $Script:CniConfigurationPath
        }

        DownloadAndExpandTarGzArchive -Url "https://github.com/containernetworking/plugins/releases/download/v$Version/cni-plugins-windows-amd64-v$Version.tgz" -DestinationPath $Script:CniPath -ErrorAction Stop
        Write-Host "Downloaded CNI binaries for the '$NetworkMode' network mode to '$Script:CniPath'."

        DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/flannel/$NetworkMode/cni/config/cni.conf" $Script:CniConfigurationPath  -ErrorAction Stop
        Write-Host "Downloaded default CNI configuration from GitHub at Microsoft/SDN."

        if ($PluginName -ieq 'flannel') {
            Get-FlanneldBinaries -Version $PluginVersion
        } else {
            throw "The '$PluginName' Container Network Interface (CNI) plugin is not supported yet."
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
        [string] $Destination = 'C:\flannel'
    )

    Process {
        if (!(Test-Path $Destination)) {
            $null = New-Item -ItemType Directory $Destination
        }

        DownloadFile -Url "https://github.com/coreos/flannel/releases/download/v$Version/flanneld.exe" -Destination (Join-Path $Destination 'flanneld.exe') -ErrorAction Stop
        Write-Host "Finished downloading Flanneld v$Version to '$Destination'"
    }
}

function Get-HnsHelperScripts {
    Param (
        [string] $Path = $Script:KubernetesClusterNodeInstallationPath,
        [switch] $Force
    )

    Process {
        Write-Host "Downloading Windows HNS helper scripts..." -NoNewLine
        $Destination = Join-Path $Path 'hns.psm1'
        DownloadFile -Url "https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1" -Destination $Destination -Force:$Force

        $null = Import-Module $Destination -ErrorAction Stop
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
        [string] $Version = '1.19.0'
    )

    Process {
        try {
            Write-Host "Downloading Kubernetes v$Version..."
            DownloadAndExpandTarGzArchive -Url "https://dl.k8s.io/v$Version/kubernetes-node-windows-amd64.tar.gz" -DestinationPath $Path
            Write-Host "Finished downloading Kubernetes v$Version"
            
            $KubernetesBinariesPath = Join-Path (Join-Path (Join-Path $Path 'kubernetes') 'node') 'bin'
            if ($env:PATH -inotmatch [Regex]::Escape($KubernetesBinariesPath)) {
                $env:PATH = "${env:PATH};$KubernetesBinariesPath"
                [Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::Machine)
                Write-Host "Added Kubernetes executables to the PATH"
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

function Get-KubernetesClusterNodeConfiguration {
    [OutputType('KubernetesClusterNodeConfiguration')]
    Param(
        [Parameter(Position = 0)]
        [string] $Path = $Script:KubernetesClusterNodeConfigurationPath
    )

    $NodeConfig = $null

    if (Test-Path $Path) {
        $NodeConfig = Get-Content $Path -Encoding UTF8 -Raw | ConvertFrom-JSON
        if ('KubernetesClusterNodeConfiguration' -notin $NodeConfig.PSObject.TypeNames) {
            $null = $NodeConfig.PSObject.TypeNames.Add('KubernetesClusterNodeConfiguration')
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

    ((& cmd /c ver) -replace '.*\[Version (.*)\]','$1').Trim()
}

function Install-ContainerNetworkInterface {
    [CmdletBinding()]
    Param (
        [string] $InterfaceName = 'Ethernet',

        #[string] $NodeIpAddress = (Get-InterfaceIpAddress),

        #[string] $NodeSubnet = (Get-InterfaceSubnet),

        #[string] $CniConfigurationPath = $Script:CniConfigurationPath,

        [string] $CniNetworkConfigurationPath = $Script:CniNetworkConfigurationPath,

        [ValidateSet('flannel','kubenet')]
        [string] $CniPluginName = 'flannel',

        [string] $CniPluginVersion = '0.13.0',

        [string] $CniPluginInstallationPath = 'C:\flannel',

        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay',

        [string] $NetworkName = 'vxlan0',

        [string] $ClusterCIDR = '10.244.0.0/16',

        #[string] $ServiceCIDR = '10.96.0.0/12',

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

                    #Set-CniConfiguration -Path $CniConfigurationPath -NodeIpAddress $NodeIpAddress -NodeSubnet $NodeSubnet -PluginName $CniPluginName -NetworkMode $NetworkMode -NetworkName $NetworkName -ClusterCIDR $ClusterCIDR -ServiceCIDR $ServiceCIDR -ErrorAction Stop
                    Set-NetConfig -Path $CniNetworkConfigurationPath -NetworkMode $NetworkMode -NetworkName $NetworkName -ClusterCIDR $ClusterCIDR -ErrorAction Stop
                                
                    New-KubernetesNetwork -InterfaceName $InterfaceName -NetworkMode $NetworkMode -ErrorAction Stop

                    $FlannelDInterfaceName = $(
                        $NetworkAdatpter = Get-NetAdapter -InterfaceAlias "vEthernet ($InterfaceName)" -ErrorAction SilentlyContinue
                        if ($NetworkAdapter) {
                            $NetworkAdapter.InterfaceAlias
                        } else {
                            $Script:Config.Node.InterfaceName
                        }
                    )

                    Install-Flanneld -Path $CniPluginInstallationPath -CniNetworkConfigurationPath $CniNetworkConfigurationPath -Version $CniPluginVersion -InterfaceName (Get-NetAdapter -InterfaceAlias "vEthernet ($InterfaceName)" -ErrorAction SilentlyContinue).InterfaceAlias -KubeConfig $KubeConfig -ErrorAction Stop <#|
                        Start-Service -ErrorAction Stop

                    <#
                    WaitForNetwork $NetworkName

                    if (!(Test-NodeRunning)) {
                        throw "Kubelet is not running and/or failed to bootstrap."
                    }
                    #>

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

        [string] $NanoServerImage = 'mcr.microsoft.com/windows/nanoserver:1809',

        [string] $ServerCoreImage = 'mcr.microsoft.com/windows/servercore:1809',

        [Parameter(Mandatory, ParameterSetName = 'PauseImage')]
        [string] $PauseImage,

        [Parameter(Mandatory, ParameterSetName = 'PauseDockerfile')]
        [string] $PauseDockerfile,

        [string] $KubeFlannelImage,

        [string] $KubeProxyImage,

        [switch] $Force
    )

    switch ($Name) {
        'dockerd' {
            Install-Dockerd -Force:$Force
            
            <#
            Write-Host "Pulling required docker images. This could take a while..."
            @(
                $NanoServerImage
                $ServerCoreImage
                $PauseImage
            ) | Get-DockerImage
            Write-Host "Docker images pulled."

            
            if (!$PauseImage) {
                Write-Host "Building the custom Kubernetes infrastructure container image 'kubeletwin/pause' based on the '$PauseDockerfile' Dockerfile..."
                New-KubernetesPauseImage $PauseDockerfile
            }
            #>
        }

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

        [string] $CniNetworkConfigurationPath = $Script:CniNetworkConfigurationPath,

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
                "--net-config-path=`"$CniNetworkConfigurationPath`""
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

function Install-Kubelet_OLD {
    [CmdletBinding()]
    Param (
        [string] $CniPath = $Script:CniPath,
        [string] $CniConfigurationPath = $Script:CniConfigurationPath,

        [string] $NodeIpAddress = (Get-InterfaceIpAddress),

        [Parameter(Mandatory)]
        [string] $DnsServiceIpAddress,
        
        [string[]] $FeatureGates
    )

    Process {
        if (!(Test-Path $Script:KubernetesClusterNodeLogPath)) {
            $null = New-Item -ItemType Directory -Path $Script:KubernetesClusterNodeLogPath
        }

        if (!(Get-Service 'kubelet' -ErrorAction SilentlyContinue)) {
            $KubeletArgs = @(
                (Get-Command 'kubelet.exe' -ErrorAction Stop).Source
                '--windows-service'
                '--v=6'
                "--log-dir=`"$Script:KubernetesClusterNodeLogPath`""
                "--cert-dir=`"$env:SYSTEMDRIVE\var\lib\kubelet\pki`""
                "--cni-bin-dir=`"$CniPath`""
                "--cni-conf-dir=`"$CniConfigurationPath`""
                '--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf'
                "--kubeconfig=$env:KUBECONFIG"
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
                $null = New-NetFirewallRule -Name KubeletAllow10250 -Description "Kubelet Allow 10250" -ACtion Allow -LocalPort 10250 -Protocol TCP -Enabled True -DisplayName "Kubelet Allow 10250 (TCP)" -ErrorAction Stop
            }
        }
    }
}

function Install-Kubelet {
    [CmdletBinding()]
    Param (
        [string] $CniConfigurationPath = $Script:CniConfigurationPath,
        [string] $CniNetworkConfigurationPath = $Script:CniNetworkConfigurationPath,
        [string] $CniPath = $Script:CniPath,
        [ValidateSet('flannel','kubenet')]
        [string] $CniPluginName = 'flannel',
        [string] $CniPluginVersion = '0.13.0',

        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay',

        [string] $NetworkName = 'vxlan0',

        [string] $InterfaceName = 'Ethernet',

        [string] $NodeIpAddress = (Get-InterfaceIpAddress),
        [string] $NodeSubnet = (Get-InterfaceSubnet),

        [string] $KubeConfig = $env:KUBECONFIG,

        [Parameter(Mandatory)]
        [string] $KubeadmToken,

        [Parameter(Mandatory)]
        [string] $KubeadmCAHash,

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
                "--kubeconfig=$env:KUBECONFIG"
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
                $null = New-NetFirewallRule -Name KubeletAllow10250 -Description "Kubelet Allow 10250" -ACtion Allow -LocalPort 10250 -Protocol TCP -Enabled True -DisplayName "Kubelet Allow 10250 (TCP)" -ErrorAction Stop
            }

            $InstallCNIParams = @{
                InterfaceName = $(
                    $NetworkAdatpter = Get-NetAdapter -InterfaceAlias "vEthernet ($InterfaceName)" -ErrorAction SilentlyContinue
                    if ($NetworkAdapter) {
                        $NetworkAdapter.InterfaceAlias
                    } else {
                        $InterfaceName
                    }
                )
                CniNetworkConfigurationPath = $CniNetworkConfigurationPath
                CniPluginName = $CniPluginName
                CniPluginVersion = $CniPluginVersion
                NetworkMode = $NetworkMode
                NetworkName = $NetworkName
                ClusterCIDR = $ClusterCIDR
                KubeConfig = $KubeConfig
            }
            Install-ContainerNetworkInterface -ErrorAction Stop @InstallCNIParams
            Write-Host "Finished installing the Container Network Interface (CNI)."

            & cmd /c kubeadm join "$(Get-ApiServerEndpoint)" --token $KubeadmToken --discovery-token-ca-cert-hash "$KubeadmCAHash" '2>&1'
            if (!$?) {
                Write-Error "Error joining cluster!"
                return
            }

            Start-Service FlannelD

            WaitForNetwork $NetworkName

            if (!(Test-NodeRunning)) {
                throw "Kubelet is not running and/or failed to bootstrap."
            }
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
                    enableDsr = $FeatureGates -match 'WinDSR=true'
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

            if ($FeatureGates -match 'WinDSR=true') {
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

function Join-KubernetesCluster {
    $Script:Config = Get-KubernetesClusterNodeConfiguration

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

    <#$InstallKubeletParams = @{
        CniPath = $Script:CniPath
        CniConfigurationPath = $Script:CniConfigurationPath
        DnsServiceIpAddress = $Script:Config.Kubernetes.Network.DnsServiceIpAddress
        NodeIpAddress = $Script:Config.Node.IpAddress
        FeatureGates = $Script:Config.Kubernetes.Kubelet.FeatureGates
    }#>
    $InstallKubeletParams = @{
        CniPath = $Script:CniPath
        CniConfigurationPath = $Script:CniConfigurationPath
        CniNetworkConfigurationPath = $Script:CniNetworkConfigurationPath
        CniPluginName = $Script:Config.Cni.Plugin.Name
        CniPluginVersion = $Script:Config.Cni.Plugin.Version
        InterfaceName = $Script:Config.Node.InterfaceName
        NetworkMode = $Script:Config.Cni.NetworkMode
        NetworkName = $Script:Config.Cni.NetworkName
        NodeIpAddress = $Script:Config.Node.IPAddress
        NodeSubnet = $Script:Config.Node.Subnet
        KubeConfig = $env:KUBECONFIG
        KubeadmToken = $Script:Config.Kubernetes.ControlPlane.JoinToken
        KubeadmCAHash = $Script:Config.Kubernetes.ControlPlane.CAHash
        ClusterCIDR = $Script:Config.Kubernetes.Network.ClusterCIDR
        ServiceCIDR = $Script:Config.Kubernetes.Network.ServiceCIDR
        DnsServiceIpAddress = $Script:Config.Kubernetes.Network.DnsServiceIpAddress
        FeatureGates = $Script:Config.Kubernetes.Kubelet.FeatureGates
    }
    Install-Kubelet -ErrorAction Stop @InstallKubeletParams
    Write-Host "Installed Kubelet as a Windows Service"
    
    <#
    $InstallCNIParams = @{
        InterfaceName = $(
            $NetworkAdatpter = Get-NetAdapter -InterfaceAlias "vEthernet ($($Script:Config.Node.InterfaceName))" -ErrorAction SilentlyContinue
            if ($NetworkAdapter) {
                $NetworkAdapter.InterfaceAlias
            } else {
                $Script:Config.Node.InterfaceName
            }
        )
        #NodeIPAddress = $Script:Config.Node.IPAddress
        #NodeSubnet = $Script:Config.Node.Subnet
        #CniConfigurationPath = $Script:CniConfigurationPath
        CniNetworkConfigurationPath = $Script:CniNetworkConfigurationPath
        CniPluginName = $Script:Config.Cni.Plugin.Name
        CniPluginVersion = $Script:Config.Cni.Plugin.Version
        NetworkMode = $Script:Config.Cni.NetworkMode
        NetworkName = $Script:Config.Cni.NetworkName
        ClusterCIDR = $Script:Config.Kubernetes.Network.ClusterCIDR
        #ServiceCIDR = $Script:Config.Kubernetes.Network.ServiceCIDR
        KubeConfig = $env:KUBECONFIG
    }
    Install-ContainerNetworkInterface -ErrorAction Stop @InstallCNIParams
    Write-Host "Finished installing the Container Network Interface (CNI)."

    <#
    & cmd /c kubeadm join "$(Get-ApiServerEndpoint)" --token $Script:Config.Kubernetes.ControlPlane.JoinToken --discovery-token-ca-cert-hash "$($Script:Config.Kubernetes.ControlPlane.CAHash)" '2>&1'
    if (!$?) {
        Write-Error "Error joining cluster!"
        return
    }

    WaitForNetwork $NetworkName

    if (!(Test-NodeRunning)) {
        throw "Kubelet is not running and/or failed to bootstrap."
    }
    #>
    
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

function New-KubernetesNodeInstallationResumptionScheduledTask {
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

function New-KubernetesFlannelImage {
    Param (
        [string] $Dockerfile,
        [string] $CniVersion = '0.8.7',
        [string] $FlannelVersion = '0.13.0',
        [switch] $Force
    )

    $Tags = @(
        ("${FlannelVersion}-windowsservercore:$(Get-WindowsBuildVersion)" -replace '\s+')
        $FlannelVersion
        'latest'
    ) | ForEach-Object { "sigwindowstools/flannel:$_" }

    if (!(docker images $Tags[0] -q) -or ($Force -and $Force.IsPresent)) {
        # Remove the old images, if present so we don't keep around unnecssary images
        $Tags | ForEach-Object { docker images rm $_ -f } -ErrorAction SilentlyContinue


    }
}

function New-KubernetesPauseContainerImage {
    Param (
        [string] $Dockerfile,
        [switch] $Force
    )

    if (!(docker images 'kubeletwin/pause' -q) -or ($Force -and $Force.IsPresent)) {
        docker build -t 'kubeletwin/pause' "$Dockerfile"
    }
}

function New-KubernetesClusterNodeConfiguration {
    [OutputType('KubernetesNodeInstallationConfiguration')]
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

        [string] $ServerCoreImage
    )

    $WinVer = Get-WindowsBuildVersion

    if (!$NanoServerImage) {
        $NanoServerImage = "mcr.microsoft.com/windows/nanoserver:$WinVer" -replace '\s+'
    }

    if (!$ServerCoreImage) {
        $ServerCoreImage = "mcr.microsoft.com/windows/servercore:$WinVer" -replace '\s+'
    }

    # If you're using a version of Windows Server 2019 that is not LTSC2019 (or 1809), then the
    # standard kube-flannel and kube-proxy images will not run on your OS version. Alse need to build
    # a custom kubernetes infrastructure image (Pause image) in this case.
    #
    # Otherwise, we can use the standard images.
    if ($WinVer -notmatch '^10\.0\.17763') {
        if (!$PauseImage) {
            $Pause = [PSCustomObject]@{
                Build = $True
                Dockerfile = 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'
                Image = ''
            }
        } else {
            $Pause = [PSCustomObject]@{
                Build = $False
                Dockerfile = ''
                Image = $PauseImage
            }
        }

        $KubeletImages = [PSCustomObject]@{
            Build = $True
            FlannelDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile'
            KubeProxyDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/kube-proxy/Dockerfile'
        }
    } else {
        $Pause = [PSCustomObject]@{ Build = $False; Image = "mcr.microsoft.com/oss/kubernetes/pause:1.3.0" }
        $KubehletImages = [PSCustomObject]@{ Build = $False }
    }

    $Script:Config = [PSCustomObject]@{
        PSTypeName = 'KubernetesClusterNodeConfiguration'
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
            }
        }
        Images = [PSCustomObject] @{
            NanoServer = $NanoServerImage
            ServerCore = $ServerCoreImage
            Pause = $Pause
            KubeletImages = $KubletImages
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
            $($EnvironmentVariable.Keys |
                ForEach-Object -Begin { $envSrc = '' } -Process {
                    $envSrc += @"
            startInfo.EnvironmentVariables["$_"] = "$($EnvironmentVariable[$_])";
"@
                } -End {
                    $envSrc
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



<# Additional steps:

1. Build custom GoLang docker build image for your version of Windows Server so that we can create custom kube-flannel and kube-proxy images later
    a. Download the dockerfile: https://raw.githubusercontent.com/docker-library/golang/master/Dockerfile-windows-servercore.template => C:\golang\Dockerfile
    b. Get the current windows version:
           PS C:\> $WinVer = ((&cmd /c ver) -replace '.*\[Version (.*)\]','$1').Trim()
    c. Update the docker file as follows and build the Golang image:
           PS C:\> (Get-Content Dockerfile -Raw) `
                       -replace 'windows/\{\{ env\.WindowsVariant \}\}:\{\{ env\.WindowsRelease \}\}', "windows/serveccore:$WinVer" `
                       -replace 'ENV GIT_VERSION 2.23.0', 'ENV GIT_VERSION 2.29.0' `
                       -replace 'ENV GIT_DOWNLOAD_SHA256 .*$', 'ENV GIT_DOWNLOAD_SHA256 b10bc7aa7222f3537071604bc7f9394e72f78a21c3c2bae24490270ba5259863' `
                       -replace 'ENV GOLANG_VERSION \{\{ .version \}\}', 'ENV GOLANG_VERSION 1.15' `
                       -replace '\{\{ .arches\["windows-amd64"\].url \}\}', 'https://storage.googleapis.com/golang/go1.15.3.windows-amd64.zip' `
                       -replace '\{\{ .arches\["windows-amd64"\].sha256 \}\}', '1d579d0e980763f60bf43afb7c3783caf63433a485731ef4d2e262878d634b3f' | Set-Content Dockerfile
           PS C:\> docker build -t golang:windowsservercore-$WinVer .

2. Build custom flannel docker image for Windows Server based on current version of node host OS:
    a. Download dockerfile for kube-flannel: https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile
           PS C:\> curl -L https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/flannel/Dockerfile -o kube-flannel.docker
    b. Build and tag the image:
           PS C:\> docker build --build-arg serverCoreTag=$WinVer --build-arg cniVersion=0.8.7 --build-arg golangTag=windowsservercore-$WinVer -t kubeletwin/flannel:$CniPluginVersion-windowsservercore-$WinVer -t kubeletwin/flannel:$CniPluginVersion -t kubeletwin/flannel:latest -f kube-flannel.docker .

3. Download the flannel-overlay.yml k8s network configuration file and transfer to master node and apply to the cluster:
    PS C:\> curl -LO https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/flannel/flannel-overlay.yml
    PS C:\> (Get-Content flannel-overlay.yml -Raw) -replace 'sigwindowstools/flannel:\d+\.\d+\.\d+$', "kubeletwin/flannel:$CniPluginVersion-windowsservercore-$WinVer"
    PS C:\> scp -o StrictHostKeyChecking=no flannel-overlay.yml "${MasterUsername}@$($MasterAddress -replace ':6443'):~/flannel-overlay.yml"
    PS C:\> ssh $MasterUsername:$($MasterAddress -replace ':6443') "kubectl apply -f flannel-overlay.yml"

4. Build custom kube-proxy docker image  for Windows Server based on current version of node host OS:
    a. Download dockerfile for kube-proxy:
           PS C:\> curl -L https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/kube-proxy/Dockerfile -o kube-proxy.docker
    b. Build and tag the image:
           PS C:\> docker build --build-arg k8sVersion="v1.19.3" --build-arg servercoreTag="$WinVer" -t kubeletwin/kube-proxy:$KubernetesVersion-windowsservercore-$WinVer -t kubeletwin/kube-proxy:$kubernetesVersion -t kubeletwin/kube-proxy:latest -f kube-proxy.docker .

3. Download the kube-proxy.yml k8s proxy configuration file and transfer to master node and apply to the cluster:
    PS C:\> curl -LO https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/kube-proxy/kube-proxy.yml
    PS C:\> (Get-Content kube-proxy.yml -Raw) -replace 'sigwindowstools/kube-proxy:VERSION$', "kubeletwin/kube-proxy:$KubernetesVersion-windowsservercore-$WinVer"
    PS C:\> scp -o StrictHostKeyChecking=no kube-proxy.yml "${MasterUsername}@$($MasterAddress -replace ':6443'):~/kube-proxy.yml"
    PS C:\> ssh $MasterUsername:$($MasterAddress -replace ':6443') "kubectl apply -f kube-proxy.yml"

#>

function New-WindowsKubernetesClusterNode {
    [CmdletBinding()]
    Param (
        [string] $ConfigurationFile,
        [switch] $Force
    )

    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

    $RequiresRestart = $False

    if ($ConfigurationFile -and (Test-Path $ConfigurationFile)) {
        $Script:Config = Get-Content $ConfigurationFile -Encoding UTF8 -Raw -ErrorAction Stop | ConvertFrom-JSON -ErrorAction Stop
        ValidateKubernetesClusterNodeConfiguration -ErrorAction Stop
        if (!Set-KubernetesClusterNodeConfiguration $Script:Config -Force:$Force) {
            while (!$resp -or $resp -ieq 'Y') {
                $resp = Read-Host "Do you want to read the existing configuration file? [Y/n] (Default 'Y') "
                $Script:Config = Get-KubernetesClusterNodeConfiguration
                ValidateKubernetesClusterNodeConfiguration -ErrorAction Stop
            }
        }
    } elseif (!$Script:Config) {
        $Script:Config = Get-KubernetesClusterNodeConfiguration
        ValidateKubernetesClusterNodeConfiguration -ErrorAction Stop
    } else {
        $Script:Config | Set-KubernetesClusterNodeConfiguration -Force:$Force
    }
    
    if (!$Script:Config) {
        Write-Error "Unable to find existing kubernetes node configuration information at '$Script:KubernetesClusterNodeInstallationPath\.kubeclusterconfig'. Please supply a Kuberentes Cluster node configuration file."
    }
     
    Write-KubernetesClusterNodeConfiguration $Script:Config

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

    $RequiresRestart = Uninstall-WindowsDefenderFeature -Force:$Force
    $RequiresRestart = $RequireRestart -or (Install-ContainersFeature -Force:$Force)
    if ($RequiresRestart) {
        if (!($Force -and $Force.IsPresent)) {
            Write-Host "In order to continue configuring Kubernetes, the server must be restarted."
            $resp = Read-HostEx "Reboot the server now? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
            if (!$resp -or $resp -ieq 'y') {
                try {
                    New-KubernetesNodeInstallationResumptionScheduledTask

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

    DownloadFile -Url "https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1" -Destination "$Script:KubernetesClusterNodeInstallationPath\hns.psm1"
    $null = Import-Module "$Script:KubernetesClusterNodeInstallationPath\hns.psm1" -WarningAction 'SilentlyContinue'

    if (!(Test-Path (Join-Path (Join-Path $env:USERPROFILE '.ssh') 'id_rsa.pub'))) {
        if (!($Force -and $Force.IsPresent)) {
            $resp = Read-HostEx "Do you wish to generate a SSH Key and add it to the Linux control-plane node? [Y/n] (Default 'Y') "
            if (!$resp -or $resp -ieq 'y') {
                New-SshKey

                Write-Host "When prompted, please enter your SSH passphrase in order to copy your public SSH key to the Linux control-plane."
                Copy-SshKey -
            }   
        } else {
            Write-Host "Generating SSH key ..."
            New-SshKey -PassPhrase ''
            cmd /c "ssh-keyscan.exe $($Script:Config.Kubernetes.ControlPlane.MasterAddress) 2>NUL" | Out-File -Encoding Utf8 (Join-Path (Join-Path $env:USERPORFILE '.ssh') 'known_hosts')
        }
    } else {
        Write-Host "If you haven't already copied your public SSH key to the Linux control-plane, please do so before joining this server to the Kubernetes cluster."
        Write-Host "Execute the following commands on the Linux control-plane node '$($Config.Kubernetes.ControlPlane.MasterAddress)' to add this Windows"
        Write-Host "node's public key to the authorized keys file:"
        Write-Host
        Write-Host "    echo $(Get-Content (Join-Path (Join-Path $env:USERPROFILE .ssh) id_rsa.pub) -Raw) >> ~/.ssh/authorized_keys"
        Write-Host
        Write-Host "Alternatively, execute the following command from another PowerShell shell on this machine:"
        Write-Host
        Write-Host "    Copy-SshKey -RemoteUsername $($Script:Config.Kubernetes.ControlPlane.MasterUsername) -RemoteHostname $($Script:Config.Kubernetes.ControlPlane.MasterAddress)"
        Write-Host
    }

    # Building some of the images below, if required, will require the Windows Server images.
    # So these images must be pulled first...
    Write-Host "Pulling required docker images. This could take a while..."
    @(
        $NanoServerImage
        $ServerCoreImage
        $PauseImage
    ) | Get-DockerImage
    Write-Host "Docker images pulled."

    # !!!!! BUILD ANY REQUIRED DOCKER IMAGES HERE !!!!!
    if ($Script:Config.Images.Pause.Build -and $Script:Config.Images.Pause.Build.IsPresent) {
        Write-Host "Building the custom Kubernetes infrastructure container image 'kubeletwin/pause' based on the '$PauseDockerfile' Dockerfile..."
        New-KubernetesPauseContainerImage $PauseDockerfile
    }

    if ($Script:Config.Images.KubeletImages.Build -and $Script:Config.Images.KubeletImages.Build.IsPresent) {
        $WinVer = Get-WindowsBuildVersion

        # Build GoLang image
        # 0. Get latest Git-For-Windows release information: MinGit 64-bit ZIP file download link and SHA-256 hash
        $LatestGfwReleasePage = Invoke-RestMethod -Method GET -Uri 'https://github.com/git-for-windows/git/release/latest'
        $result = $LatestGfwReleasePage -match '<td>MinGit-(?<Version>\d+\.\d+\.\d+)-64-bit\.zip</td>\s+<td>(?<Hash>.*)</td>'
        if (!$result) {
            Write-Error "Unable to find a link to download the latest Git for Windows MinGit release and/or it's SHA-256 authenticity hash in order to build a custom GoLang Docker container image which is required for building OS-specific Kuberenetes infrastructure docker container images."
            return
        }

        $LatestMinGitGfwReleaseVersion = $Matches.Version
        $LatestMinGitGfwReleaseHash = $Matches.Hash
        
        # 1. Get the GoLang docker file to be used to build a custom GoLang build docker container image
        $GoLangVersionInfo = Invoke-RestMethod -Method GET -Uri 'https://raw.githubusercontent.com/docker-library/golang/master/versions.json'
        $GoLangLatestVersion = $GoLangVersionInfo.PSObject.Properties | Select-Object -Last 1 -ExpandProperty Name
        $GoLangDockerfileTemplate = Invoke-RestMethod -Method GET -Uri 'https://raw.githubusercontent.com/docker-library/golang/master/Dockerfile-windows-servercore.template'
        $GoLangDockerfileTemplate `
            -replace '\{\{\s+env\.WindowsVariant\s+\}\}:\{\{\s+env\.WindowsRelease\s+\}\}', "windows/servercore:$WinVer" `
            -replace 'ENV GIT_VERSION 2.23.0', "ENV GIT_VERSION $LatestMinGitGfwReleaseVersion" `
            -replace 'ENV GIT_DOWNLOAD_SHA256\s+.*$', "ENV GIT_DOWNLOAD_SHA256 $LatestMinGitGfwReleaseHash" `
            -replace '\{\{\s+\.arches\["windows-amd64"\]\.url\s+\}\}', "$($GoLangVersionInfo."$GoLangLatestVersion".arches.url)" `
            -replace '\{\{\s+\.arches\["windows-amd64"\]\.sha256\s+\}\}', "$($GoLangVersionInfo."$GoLangLatestVersion".arches.sha256)" |
            Set-Content golang.dockerfile

        docker build -t golang:windowsservercore-$WinVer -t golang:windowsservercore-latest -t golang:latest -f golang.dockerfile .

        # Build custom Flannel image, update default flannel-overlay.yml, and apply it to the cluster
        Invoke-RestMethod -Method GET -Uri 'https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/flannel/Dockerfile' -Outfile kube-flannel.dockerfile
        docker build --build-arg serverCoreTag=$WinVer --build-arg cniVersion=$Script:Config.Cni.Version --build-arg golangTag=windowsservercore-$WinVer -t kubeletwin/flannel:$($Script:Config.Cni.Plugin.Version)-windowsservercore-$WinVer -t kubeletwin/flannel:$($Script:Config.Cni.Plugin.Version) -t kubeletwin/flannel:latest -f kube-flannel.dockerfile .

        $FlannelYmlName = "flannel-$(if ($Script:Config.Cni.NetworkMode -ieq 'overlay') { 'overlay' } else { 'host-gw' }).yml"
        $FlannelYml = Invoke-RestMethod -Method GET -Uri "https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/flannel/$FlannelYmlName"
        # This code does not yet support host-gw...
        $FlannelYml -replace 'sigwindowstools/flannel:\d+\.\d+\.\d+$', "kubeletwin/flannel:$($Script:Config.Cni.Plugin.Version)-windowsservercore-$WinVer"
        Set-Content -Path $FlannelYmlName -Value $FlannelYml
        scp -o StrictHostKeyCHecking=no $FlannelYmlName "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'):~/$FlannelYmlName"
        ssh "$($Script:Config.Kubernetes.ControlPlane.Username):$($Script:Config.Kuberenetes.ControlPlane.Address -replace ':6443')" "kubectl apply -f $FlannelYmlName"
        
        # Build custom Kube-Proxy image, update default kube-proxy.yml, and apply it to the cluster
        Invoke-RestMethod -Method GET -Uri 'https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/kube-proxy/Dockerfile' -Outfile kube-proxy.dockerfile
        docker build --build-arg k8sVersion=v$($Script:Config.Kubernetes.Version) --build-arg servercoreTag=$WinVer -t kubeletwin/kube-proxy:$($Script:Config.Kubernetes.Version)-windowsservercore-$WinVer -t kubeletwin/kube-proxy:$($Script:Config.Kubernetes.Version) -t kubeletwin/kube-proxy:latest -f kube-proxy.dockerfile .

        $KubeProxyYml = Invoke-RestMethod -Method GET -Uri "https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/kube-proxy/kube-proxy.yml"
        $KubeProxyYml -replace 'sigwindowstools/kube-proxy:VERSION$', "kubeletwin/kube-proxy:$($Script:Config.Kubernetes.Version)-windowsservercore-$WinVer"
        Set-Content -Path kube-proxy.yml -Value $KumePlobyYml
        scp -o StrictHostKeyCHecking=no kube-proxy.yml "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':6443'):~/kube-proxy.yml"
        ssh "$($Script:Config.Kubernetes.ControlPlane.Username):$($Script:Config.Kuberenetes.ControlPlane.Address -replace ':6443')" "kubectl apply -f kube-proxy.yml"
    }
    # !!!!! END BUILD ANY REQUIRED DOCKER IMAGES

    # !!!!! TODO: GET RID OF CONTAINER BUILDING AND RETRIEVAL PARAMETERS
    $InstallCriParams = @{
        NanoServerImage = "$($Script:Config.Images.NanoServer)"
        ServerCoreImage = "$($Script:Config.Images.ServerCore)"
    }
    if ($Script:Config.Images.Pause.Build) {
        $InstallCriParams += @{ PauseDockerfile = $Script:Config.Images.Pause.Dockerfile }
    } else {
        $InstallCriParams += @{ PauseImage = "$($Script:Config.Images.Pause.Image)" }
    }
    Install-ContainerRuntimeInterface -Name $Script:Config.Cri.Name -Force:$Force @InstallCriParams
    Get-KubernetesBinaries -Version $Script:Config.Kubernetes.Version
    Get-CniBinaries -Version $Script:Config.Cni.Version -NetworkMode $Script:Config.Cni.NetworkMode -PluginName $Script:Config.Cni.Plugin.Name -PluginVersion $Script:Config.Cni.Plugin.Version

    <#
    if (!(Test-Path (Join-Path (Join-Path $env:USERPROFILE '.ssh') 'id_rsa.pub'))) {
        if (!($Force -and $Force.IsPresent)) {
            $resp = Read-HostEx "Do you wish to generate a SSH Key and add it to the Linux control-plane node? [Y/n] (Default 'Y') "
            if (!$resp -or $resp -ieq 'y') {
                New-SshKey

                Write-Host "When prompted, please enter your SSH passphrase in order to copy your public SSH key to the Linux control-plane."
                Copy-SshKey -
            }   
        } else {
            Write-Host "Generating SSH key ..."
            New-SshKey -PassPhrase ''
            cmd /c "ssh-keyscan.exe $($Script:Config.Kubernetes.ControlPlane.MasterAddress) 2>NUL" | Out-File -Encoding Utf8 (Join-Path (Join-Path $env:USERPORFILE '.ssh') 'known_hosts')
        }
    } else {
        Write-Host "If you haven't already copied your public SSH key to the Linux control-plane, please do so before joining this server to the Kubernetes cluster."
        Write-Host "Execute the following commands on the Linux control-plane node '$($Config.Kubernetes.ControlPlane.MasterAddress)' to add this Windows"
        Write-Host "node's public key to the authorized keys file:"
        Write-Host
        Write-Host "    echo $(Get-Content (Join-Path (Join-Path $env:USERPROFILE .ssh) id_rsa.pub) -Raw) >> ~/.ssh/authorized_keys"
        Write-Host
        Write-Host "Alternatively, execute the following command from another PowerShell shell on this machine:"
        Write-Host
        Write-Host "    Copy-SshKey -RemoteUsername $($Script:Config.Kubernetes.ControlPlane.MasterUsername) -RemoteHostname $($Script:Config.Kubernetes.ControlPlane.MasterAddress)"
        Write-Host
    }
    #>

    $Task = Get-ScheduledTask -TaskName 'KubernetesNodeBootstrap' -ErrorAction SilentlyContinue
    if ($Task) {
        $Task | Unregister-ScheduledTask -Confirm:$False
        Write-Host 'Unregistered KubernetesNodeBootstrap scheduled task, as all prerequisite setup has been completed.'
    }

    if (!($Force -and $Force.IsPresent)) {
        $resp = Read-HostEx "Would you like to join this server to the Kubernetes cluster now? [y/N] (Default 'N') " -ExpectedValue 'y','N'
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

            if ($Script:Config.Cri -ieq 'dockerd') {
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

            if ($Config.Cri -ieq 'dockerd') {
                $CniConfig.delegate.policies[0].Value.DestinationPrefix = $ServiceCIDR
            } else {
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
        
        Set-Content -Path $Path -Value (ConvertTo-JSON $CniConfig -Depth 100) -Force
        
        Write-Host "Generated CNI configuration:`r`n`r`n$CniConfig`r`n`r`n"
    }
}

function Set-KubernetesClusterNodeConfiguration {
    [CmdletBinding()]
    [OutputType([Boolean])]
    Param (
        [Parameter(Position = 0)]
        [string] $Path = (Join-Path (Join-Path $env:ALLUSERSPROFILE 'Kubernetes') '.kubeclusternodeconfig'),

        [Parameter(ValueFromPipeline)]
        [PSTypeName('KubernetesClusterNodeConfiguration')]
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
        [string] $Path = $Script:CniNetworkConfigurationPath,

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

        Set-Content -Path $Path -Value (ConvertTo-JSON $NetConfig -Depth 100)
        
        Write-Host "Generated net-conf Config:`r`n`r`n$NetConfig`r`n`r`n"
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

function Write-KubernetesClusterNodeConfiguration {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [PSTypeName('KubernetesClusterNodeConfiguration')]
        [PSCustomObject] $Config = $Script:Config
    )

    Write-Host
    Write-Host '########################################################################################################################'
    Write-Host
    Write-Host 'This is the Kubernetes Cluster Node Configuration data which will be used to configure this node:'
    Write-Host
    Write-Host "    Container Runtime Interface: $($Script:Config.Cri.Name)"
    Write-Host '    Container Network Interface:'
    Write-Host "        Mode:    $($Script:Config.Cni.NetworkMode)"
    Write-Host "        Name:    $($Script:Config.Cni.NetworkName)"
    Write-Host "        Version: $($Script:Config.Cni.Version)"
    Write-Host "        Plugin:  $($Script:Config.Cni.Plugin.Name) v$($Script:Config.Cni.Plugin.Version)"
    Write-Host '    Kubernetes:'
    Write-Host "        Version: v$($Script:Config.Kubernetes.Version)"
    Write-Host '        Control Plane Information:'
    Write-Host "            Master Node Address: $($Script:Config.Kubernetes.ControlPlane.Address)"
    Write-Host "            Username:            $($Script:Config.Kubernetes.ControlPlane.Username[0])$("*" * 8)$($Script:Config.Kubernetes.ControlPlane.Username[-1])"
    Write-Host "            Join Token:          $("*" * ($Script:Config.Kubernetes.ControlPlane.JoinToken.Length - 4))$($Script:Config.Kubernetes.ControlPlane.JoinToken.Substring($Script:Config.Kubernetes.ControlPlane.JoinToken.Length - 4))"
    Write-Host "            CA Hash:             $("*" * ($Script:Config.Kubernetes.ControlPlane.CAHash.Length - 8))$($Script:Config.Kubernetes.ControlPlane.CAHash.Substring($Script:Config.Kubernetes.ControlPlane.CAHash.Length - 8))"
    Write-Host '        Network Information:'
    Write-Host "            Cluster CIDR:           $($Script:Config.Kubernetes.Network.ClusterCIDR)"
    Write-Host "            Service CIDR:           $($Script:Config.Kubernetes.Network.ServiceCIDR)"
    Write-Host "            DNS Service IP Address: $($Script:Config.Kubernetes.Network.DnsService.IPAddress)"
    Write-Host '    Node Interface Information:'
    Write-Host "        Name:            $($Script:Config.Node.InterfaceName)"
    Write-Host "        IP Address:      $($Script:Config.Node.IPAddress)"
    Write-Host "        Subnet:          $($Script:Config.Node.Subnet)"
    Write-Host "        Default Gateway: $($Script:Config.Node.DefaultGateway)"
    Write-Host '    Docker Images:'
    Write-Host "        Nano Server Image: $($Script:Config.Images.NanoServer)"
    Write-Host "        Server Core Image: $($Script:Config.Images.ServerCore)"
    Write-Host '        Pause Image:'
    Write-Host "            Build? $(if ($Script:Config.Images.Pause.Build) { '     Yes' } else  { 'No' })"
    Write-Host "            $(if ($Script:Config.Images.Pause.Build) { "Dockerfile: $($Script:Config.Images.Pause.Dockerfile)" } else { "Image:      $($Script:Config.Images.Pause.Image)" })"
    Write-Host
    Write-Host "########################################################################################################################"
    Write-Host
}
