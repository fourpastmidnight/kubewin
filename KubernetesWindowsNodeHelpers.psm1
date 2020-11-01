$ProgressPreference = 'SilentlyContinue'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

function AuthorizeSshPublicKey {
    Param (
        [Parameter(ValueFromPipeline)]
        [Alias('i')]
        [string] $PublicSshIdentityFile,

        [Parameter(Position = 0, Mandatory)]
        [string] $RemoteHost,

        [Parameter(Position = 1, Mandatory)]
        [string] $RemoteUsername,

        [Parameter(Position = 2)]
        [int] $Port = 22
    )

    Process {
        Write-Host "Adding your SSH key to the SSH Agent is a convenient and more secure way to interact with SSH."
        Write-Host "If you've already added your SSH key to the SSH Agent, you can answer 'N'."
        Write-Host "If you're not sure if you've added your SSH key to the SSH agent, answer 'Y'. Your key will not be added twice."
        Write-Host
        $resp = Read-HostEx "Would you like to add your SSH key to the SSH Agent? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
        if (!$resp -or $resp -ieq 'y') {
            Write-Host "Follow the on-screen prompts to add your SSH key to the SSH Agent."
            Write-Host

            $SshConfigPath = Join-Path (Join-Path $env:USERPRofile .ssh) config
            if ((Test-Path $SshConfigPath)) {
                $SshConfig = Get-Content $SshConfigPath -Raw
                if ($SshConfig -inotmatch "(?m)^\s*Host\s+$RemoteHost\s*$") {
                    @'
Host k8s-master
    AddKeysToAgent yes
    IdentitiesOnly yes
'@ | Set-Content -Path $SshConfigPath
                } else {
                    @'

Host k8s-master
    AddKeysToAgent yes
    IdentitiesOnly yes
'@ | Add-Content -Path $SshConfigPath
                }
            }

            # Set the proper ACLs on the key file, or SSH won't let you copy it
            icacls.exe $PublicSshIdentityFile /c /t /Inheritance:d
            icacls.exe $PublicSshIdentityFile /c /t /Grant ${env:USERNAME}:F
            icacls.exe $PublicSshIdentityFile /c /t /Remove Administrator "Authenticated Users" BUILTIN\Administrator BUILTIN Everyone System Users

            ssh-add.exe $PublicSshIdentityFile
        } else {
            Write-Host
            Read-HostEx "Whenever connecting to $RemoteHost via SSH, you will be prompted for your SSH key passphrase. [OK] "
            Write-Host
        }
        
        Write-Host "Please follow the on-screen prompts to authorize your public SSH key on $RemoteHost."
        Copy-SshKey -i $PublicSshIdentityFile $RemoteUsername $RemoteHost $Port
    }
}

function ConfigureFirewall {
    Param (
        [switch] $Force
    )

    Process {
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
    }
}

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
        $OriginalProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        try {
            $ZipFile = New-TemporaryFile | Rename-Item -NewName { $_ -replace 'tmp$','zip' } -PassThru
            DownloadFile -Url $Url -Destination $ZipFile -Force
            Expand-Archive $ZipFile.FullName $DestinationPath
            Remove-Item $ZipFile
        } catch {
            throw
        } finally {
            $ProgressPreference = $OriginialProgressPreference
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
                curl.exe -sL $Url | ForEach-Object -Begin { $result = New-Object System.Text.StringBuilder } -Process { $result = $result.AppendLine($_) } -End { $result.ToString() }
            } else {
                $Path = Split-Path $Destination -Parent
                if ($Path -and !(Test-Path $Path)) {
                    $null = New-Item -ItemType Directory -Path $Path
                }

                curl.exe -sL $Url -o $Destination
                Write-Host "Downloaded [$Url] => [$Destination]"
            }
        } catch {
            Write-Error "Failed to download '$Url'"
            throw
        }
    }
}

function LoadAndValidateKubernetesWindowsNodeConfiguration {
    [OutputType('KubernetesWindowsNodeConfiguration')]
    Param (
        [Parameter(Position = 0)]
        [string] $Path,
        [switch] $Force
    )

    Process {
        if ($Path -and (Test-Path $Path)) {
            $Script:Config = Get-KubernetesWindowsNodeConfiguration -Path $Path -ErrorAction Stop
            ValidateKubernetesWindowsNodeConfiguration -ErrorAction Stop
            if ($Path -ine $Script:KuberenetesClusterNodeConfigurationPath -and !(Set-KubernetesWindowsNodeConfiguration $Script:KubernetesClusterNodeConfigurationPath -Force:$Force)) {
                $resp = Read-HostEx "Do you want to read the existing configuration file? [Y/n] (Default 'Y') " -ExpectedValue 'Y','n'
                if (!$resp -or $resp -ieq 'y') {
                    $Script:Config = Get-KubernetesWindowsNodeConfiguration
                    ValidateKubernetesWindowsNodeConfiguration -ErrorAction Stop
                }
            }
        }
        
        if (!$Script:Config) {
            $Script:Config = Get-KubernetesWindowsNodeConfiguration -ErrorAction Stop
            ValidateKubernetesWindowsNodeConfiguration -ErrorAction Stop
        }
    
        if (!$Script:Config) {
            Write-Error "Unable to find existing kubernetes node configuration information at '$Script:KubernetesClusterNodeInstallationPath\.kubeclusterconfig'. Please supply a Kuberentes Cluster node configuration file."
        }
    }
}

function SetupSshAccessToControlPlane {
    Param (
        [string] $RemoteHost,
        [string] $RemoteUsername,
        [int] $Port = 22,
        [switch] $Force
    )

    Process {
        # If running interactively...
        if (!($Force -and $Force.IsPresent)) {
            Write-Host "While preparing this server to become a Kubernetes worker node, some configuration is required on $RemoteHost.
You will not be able to join this server to the cluster until $RemoteHost is configured. It is highly advised to setup
an SSH key that is authorized on $RemoteHost so that these configuration tasks can be performed by this script with
minimal intervention.

"
            $resp = Read-HostEx "Would you like to authorize an SSH key on ${RemoteHost}? [Y|n] (Default 'Y') "
            if (!$resp -or $resp -ieq 'y') {

                # This is the default location for user identity files.
                $PublicSshIdentityFile = Get-ChildItem "${env:USERPROFILE}\.ssh\*.pub" -File -ErrorAction SilentlyContinue
                if ($PublicSshIdentityFile -and $PublicSshIdentityFile -is [Array]) {
                    $PublicSshIdentityFile = ''
                }

                if (!$PublicSshIdentityFile) {
                    Write-Host "Either an SSH key identity file was not found in '$env:USERPROFILE\.ssh', or more than one SSH key identity
file was found."
                    $resp = Read-HostEx "Do you want to specify the location of the identity file to use? [Y|n] (Default 'Y') " -ExpectedValue 'Y','n'

                    if ($resp -ieq 'y') {
                        Write-Host
                        Write-Host "Please provide the path and file name of the public SSH key identity file to use."
                        Write-Host "If you typed 'y' accidentally, please type 'QUIT' at the prompt to abort this process."
                        Write-Host
                        $PublicSshIdentityFile = Read-HostEx "Public SSH key identity file location" -ValueRequired
                        if ($PublicSshIdentityFile -ne 'QUIT') {
                            AuthorizeSshPublicKey -i $PublicSshIdentityFile $RemoteUsername $RemoteHost $Port -ErrorAction Stop
                            return
                        }
                    } else {
                        $resp = Read-HostEx "Would you like to create an SSH key now? [Y|n] (Default 'Y') "
                        if (!$resp -or $resp -ieq 'y') {
                            Write-Host "Please follow the on-screen prompts to generate a SSH public and private key pair."
                            ssh-keygen.exe

                            $PublicSshIdentityFile = Get-ChildItem "${env:USERPROFILE}\.ssh\*.pub" | Select-Object -First 1
                            AuthorizeSshPublicKey -i $PublicSshIdentityFile $RemoteUsername $RemoteHost $Port -ErrorAction Stop
                            return
                        }
                    }
                } else {
                    # We found a public SSH key identity file. Ask if the user wants to:
                    #     Add the key to the ssh-agent
                    #     Authorize the key with the lunix conttrol plane

                    Write-Host "A SSH public key identity file was found at '$PublicSshIdentityFile'."
                    Write-Host

                    $resp = Read-HostEx "Would you like to authorize the public SSH key with ${RemoteHost}? [Y|n] (Default 'Y') "
                    if (!$resp -or $resp -ieq 'y') {
                        AuthorizeSshPublicKey -i $PublicSshIdentityFile $RemoteUsername $RemoteHost $Port -ErrorAction Stop
                        return
                    }
                }
            }
        }

        # >>>>>>>>> TODO: Fix getting module's path!!
        Write-Host @"
Either you specified '-Force' when preparing this server as a Kubernetes cluster worker node, or you chose not to
create and/or authorize a SSH public/private key pair with $RemoteHost.

After this server has been prepared as a Kubernetes worker node, the following tasks must be completed before the
node can be joined to the cluster:

1. Import this script module:

    PS C:\> Import-Module $($Script:MyInvocation.PSCommandPath)

2. Generate a public/private SSH key pair if you have not done so already.

    PS C:\> ssh-keygen.exe

3. Optionally, but highly recommended, add your newly generated SSH key to the ssh-agent:

    PS C:\> @'
Host $RemoteHost
    AddKeysToAgent yes
    IdentitiesOnly yes
'@ | Add-Content -Path $(Join-Path (Join-Path $env:USERPROFILE .ssh) config)

    PS C:\> ssh-add.exe

4. Add $RemoteHost as a known host:

    PS C:\> ssh-keyscan.exe $RemoteHost 2>`$null | Out-File $(Join-Path (Join-Path $env:USERPROFILE .ssh) known_hosts)

5. Add your SSH key as an authorized key on ${RemoteHost}:

    PS C:\> Copy-SshKey -i $env:USERPROFILE\.ssh\id_rsa.pub $RemoteUsername $RemoteHost$(if ($Port -ne 22) { ":$Port" })

"@

        pause
    }

    
}

function ShouldBuildCustomFlannelDockerContainerImage {
    [OutputType([boolean])]
    Param (
        [Parameter(Position = 0, Mandatory)]
        [string] $FlannelVersion,

        [Parameter(Position = 1)]
        [ValidateSet('overlay','l2bridge')]
        [string] $NetworkMode = 'overlay'
    )

    Process {
        # Given the desired flannel version to use, and the network mode being employed
        # in the Kubernetes cluster, determine whether or not a custom Flannel Docker
        # container image will be required.
        #
        # The image in the DaemonSet defaults to Flannel 0.12.0. But, for example, this
        # version is known to have a bug that is resolved in Flannel 0.13.0. So this is
        # why someone may specify a different version of flannel--and the DaemonSet will
        # then need to be updated.

        $FlannelDaemonSetYamlUrl = "https://github.com/kubernetes-sigs/sig-windws-tools/raw/master/kubeadm/flannel/flannel-$(if ($NetworkMode -ieq 'overlay') { 'overlay' } else { 'host-gw' }).yml"
        $FlannelDaemonSetYml = (Split-Path $FlannelDaemonSetYamlUrl -Leaf)

        try {
            curl.exe -sLO $FlannelDaemonSetYamlUrl
            (Get-Content $FlannelDaemonSetYml -Raw -ErrorAction Stop) -match '(?m)sigwindowstools/flannel:(?<Version>\d+\.\d+\.\d+)$'

            $FlannelVersion -ne $Matches.Version
        } finally {
            Remove-Item $FlannelDaemonSetYml -Force -ErrorAction SilentlyContinue
        }
    }
}

# TODO: I try to be nice and fill in "reasonable" defaults, such as using Flannel for CNI
#       when no CNI information is given. But really, should I? Why not just fail with
#       errors? I mean, I have New-KubernetesWindowsNodeConfiguration cmdlet that can
#       walk you through constructing a proper configuration object....
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
                $Script:Config.Kubernetes = $Script:Config.Kubernetes | Add-Configuration 'Version' '1.19.3' -Force
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

            if (!$Script:Config.Cni.Version) {
                $Script:Config.Cni | Add-Configuration 'Version' '0.8.7' -Force
                Write-Host "'Cni.Version' was not specified. Using 'v$($Script:Config.Cni.Version)'."
            }

            if (!$Script:Config.Cni.Plugin) {
                if ($Script:Config.Cni.NetworkMode -iin 'overlay','l2bridge') {
                    $Script:Config.Cni | Add-Configuration 'Plugin' ([PSCustomObject]@{
                        Name = 'flannel'
                        Version = '0.13.0'
                        WindowsDaemonSetUrl = "https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/flannel/flannel-$(if ($Script:Config.NetworkMode -ieq 'overlay') { 'overlay' } else { 'host-gw' }).yml"
                    })
                    Write-Host "A 'Cni.Plugin' was not specified. Using '$($Script:Config.Cni.Plugin.Name) v$($Script:Config.Cni.Plugin.Version)'."
                } else {
                    $Errors += 'Missing ''Cni.Plugin''.'
                }
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
                } elseif ($Script:Cni.Plugin.Name -eq 'flannel' -and (ShouldBuildCustomFlannelDockerContainerImage -FlannelVersion $Script:Config.Cni.Plugin.Version -NetworkMode $Script:Config.Cni.NetworkMode)) {
                    [PSCustomObject]@{
                        Build = $True
                        FlannelDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile'
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
                } elseif ($Script:Cni.Plugin.Name -eq 'flannel' -and (ShouldBuildCustomFlannelDockerContainerImage -FlannelVersion $Script:Config.Cni.Plugin.Version -NetworkMode $Script:Config.Cni.NetworkMode)) {
                    [PSCustomObject]@{
                        Build = $True
                        FlannelDockerfile = 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile'
                    }
                } else {
                    $InfrastructureImages = [PSCustomObject]@{
                        Build = $False
                        Pause = 'mcr.microsoft.com/oss/kubernetes/pause:1.3.0'
                    }
                })

                Write-Host 'An ''Images.Infrastructure'' section was not found. Using the following images:'
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

.PARAMETER PublicSshIdentityFile

The path and filename of the public SSH key to copy.

.PARAMETER RemoteUsername

The username with which to connect to the remote machine and to which to add the
public SSH key as an authorized key.

.PARAMETER RemoteHostname

The name of the remote host to connect to.

.PARAMETER Port

The port number that should be used when connecting to the remote host over SSH. The default is 22.

#>
function Copy-SshKey {
    Param (
        [Parameter(Position = 0, Mandatory)]
        [Alias('i')]
        [string] $PublicSshIdentityFile,

        [Parameter(Position = 1, Mandatory)]
        [string] $RemoteUsername,

        [Parameter(Position = 2, Mandatory)]
        [string] $RemoteHostname,

        [Parameter(Position = 3)]
        [int] $Port
    )

    Process {
        $AddAuthorizedKeyCommand = "PUB_KEY=\`"$(Get-Content $PublicSshIdentityFile)\`" ; grep -q -F \`"`$PUB_KEY\`" ~/.ssh/authorized_keys 2>/dev/null || echo \`"`$PUB_KEY\`" >> ~/.ssh/authorized_keys"
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
        [string] $DestinationPath = $Script:KubernetesClusterNodeInstallationPath,

        [Parameter(Position = 1)]
        [string] $Version = '1.19.3',

        [switch] $Force
    )

    Process {
        $Version = $Version.ToLower().TrimStart('v');

        try {
            if ((Test-Path (Join-Path $DestinationPath kubelet.exe)) -and $Force -or $Force.IsPresent) {
                Remove-Item -Path $DestinationPath\kube*.exe -Force
            }

            if (!(Test-Path (Join-Path $DestinationPath kubelet.exe))) {
                Write-Host "Downloading Kubernetes v$Version..."
                DownloadAndExpandTarGzArchive -Url "https://dl.k8s.io/v$Version/kubernetes-node-windows-amd64.tar.gz" -DestinationPath $Pwd
                Write-Host "Finished downloading Kubernetes v$Version"

                Move-Item $Pwd\kubernetes\node\bin\*.exe $DestinationPath
            
                if ($env:PATH -inotmatch [Regex]::Escape($DestinationPath)) {
                    $env:PATH = "${env:PATH};$DestinationPath" -replace ';;',';'
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

function Install-Kubelet {
    [CmdletBinding()]
    [OutputType([System.ServiceProcess.ServiceController])]
    Param (
        [string] $KubeConfig = $env:KUBECONFIG,
        
        [string[]] $FeatureGates
    )

    Process {
        if (!(Test-Path $Script:KubernetesClusterNodeLogPath)) {
            $null = New-Item -ItemType Directory -Path $Script:KubernetesClusterNodeLogPath
        }

        $KubeletSvc = Get-Service 'kubelet' -ErrorAction SilentlyContinue
        if (!$KubeletSvc) {
            $KubeletArgs = @(
                "--cert-dir=`"$(Join-Path $env:SystemDrive var\lib\kubelet\pki)`""
                '--bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf'
                "--kubeconfig=$KubeConfig"
                "--hostname-override=$($env:COMPUTERNAME.ToLower())"
                '--pod-infra-container-image=kubeletwin/pause'
                '--enable-debugging-handlers'
                '--cgroups-per-qos=false'
                '--enforce-node-allocatable=""'
                '--network-plugin=cni'
                '--resolv-conf=""'
                "--log-dir=`"$Script:KubernetesClusterNodeLogPath`""
                '--logtostderr=false'
                '--image-pull-progress-deadline=20m'
                '--v=6'
            )

            if ($FeatureGates) {
                $KubeletArgs += "--feature-gates=$($FeatureGates -join ',')"
            }

            $StartKubeletPath = (Join-Path $Script:KubernetesClusterNodeInstallationPath StartKubelet.ps1)

            @"
`$KubeletArgs = (Get-Content -Path '/var/lib/kubelet/kubeadm-flags.env' -Raw).Trim('KUBELET_KUBEADM_ARGS=') -replace '^"(.*)"`$','`$1'

if (!(docker network ls -f name=host -q)) {
    docker network create -d nat host
}

`$KubeletCmd = '$((Get-Command 'kubelet.exe' -ErrorAction Stop).Source) `$KubeletArgs $KubeletArgs'

Invoke-Expression `$KubeletCmd
"@ | Set-Content $StartKubeletPath

            nssm.exe install kubelet (Get-Command powershell.exe).Source -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $StartKubeletPath
            nssm.exe set kubelet DisplayName Kubelet
            nssm.exe set kubelet AppDirectory $Script:KubernetesClusterNodeInstallationPath
            nssm.exe set kubelet DependOnService docker

            if (!(Get-NetFirewallRule -Name KubeletAllow10250 -ErrorAction SilentlyContinue)) {
                $null = New-NetFirewallRule -Name KubeletAllow10250 -Description "Kubelet Allow 10250" -Action Allow -LocalPort 10250 -Protocol TCP -Enabled True -DisplayName "Kubelet Allow 10250 (TCP)" -ErrorAction Stop
            }

            $KubeletSvc = Get-Service kubelet -ErrorAction Stop
        }

        $KubeletSvc
    }
}

function Install-Nssm {
    $InstallDir = (Join-Path $env:ProgramFiles nssm)
    if (!(Test-Path $InstallDir)) {
        $null = New-Item -ItemType Directory -Path $InstallDir -Force
    }

    $arch = 'win32'
    if ([Environment]::Is64BitOperatingSystem) {
        $arch = 'win64'
    }

    DownloadFile -Destination nssm.zip -Url https://k8stestinfrabinaries.blob.core.windows.net/nssm-mirror/nssm-2.24.zip
    tar.exe C $InstallDir -xvf .\nssm.zip --strip-components 2 */$arch/*.exe
    Remove-Item -Force .\nssm.zip

    if ($env:PATH -inotmatch [Regex]::Escape(";$InstallDir")) {
        $env:PATH = "$env:PATH;$InstallDir" -replace ';;',';'
        [Environment]::SetEnvironmentVariable('PATH',$env:PATH,[EnvironmentVariableTarget]::Machine)
    }
}

function Install-PowerShellWin32OpenSSH {
    [CmdletBinding()]
    Param (
        [string] $DestinationPath = 'C:\OpenSSH',

        [ValidatePattern('(?i)^(latest|v?\d+\.\d+\.\d+\.\d+p\d+-.*)$')]
        [string] $Version = 'latest',

        [switch] $Force
    )

    Process {
        # Get the version number of SSSH to be installed
        if ($Version -ieq 'latest') {
            $SSHReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/powershell/win32-openssh/releases/latest'

            # Get the latest Win32-OpenSSH release metadata
            $SshVersionToInstall = [Version]($SSHReleaseMetadata.name -replace '^(?i)v' -replace 'p.*$')
        } else {
            $SshVersionToInstall = [Version]($Version -ireplace '^v' -ireplace 'p\d+-.*$')
            $SSHReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/powershell/win32-openssh/releases' |
                Where-Object { $_.'tag_name' -imatch $Version }

            if (!$SSHReleaseMetadata) {
                Write-Error "Unable to find PowerShell/Win32-OpenSSH $Version release at GitHub."
                return
            }
        }

        try {
            # Even though the Windows OpenSSH capability may have been removed, it's possible someone installed another
            # distribution of OpenSSH on the machine. Check for this case. If the installed version is newer than the one
            # being requested to install, then don't do anything. Otherwise, install the new version.
            Write-Host "Checking if OpenSSH is installed..."
            $SshExe = Get-Command ssh.exe -ErrorAction SilentlyContinue
            if (!($Force -and $Force.IsPresent) -and $SshExe) {
                if ($SshExe.FileVersionInfo.ProductVersionRaw -lt [Version]$SshVersionToInstall) {
                    Write-Host "Found OpenSSH v$($SshExe.ProductVersion). Installing OpenSSH v$SshVersionToInstall."
                } else {
                    Write-Host "Found OpenSSH v$($SshExe.ProductVersion). Skipping installation of OpenSSH v$SshVersionToInstall."
                    return
                }
            } else {
                Write-Host "Installing OpenSSH v$SshVersionToInstall."
            }

            # Remove any existing SSH services
            $Sshd = Get-Service sshd -ErrorAction SilentlyContinue
            if ($Sshd)
            {
                $SshdStartupType = $Sshd.StartType
                $SshdIsRunning = $Sshd.Status -eq 'Running'
                Write-Host "Stopping and removing Sshd service..."
                $sshd | Stop-Service
                sc.exe delete sshd 1>$null
            }

            if (Get-Service ssh-agent -ErrorAction SilentlyContinue) {
                Write-Host "Stopping and removing Ssh-Agent service..."
                Stop-Service ssh-agent
                sc.exe delete ssh-agent 1>$null
            }

            # Remove the existing installation files, unless located in C:\Windows\System32\OpenSSH (or system eqivalent)
            if ($SshPath -and $SshPath -inotmatch [Regex]::Escape((Join-Path (Join-Path $env:WinDir system32) openssh))) {
                $OpenSshInstallPath = Split-Path $SshPath -Parent
                Write-Host "Removing existing installation of OpenSSH at $OpenSshInstallPath..."
                Remove-Item $OpenSshInstallPath -Recurse -Force
            }

            # Remove any existing PATH spec  for OpenSSH
            if ($env:PATH -imatch 'openssh') {
                $env:PATH = (($env:PATH -split ';') | Where-Object {
                    $_ -inotmatch 'openssh$' -or $_ -imatch "c:\\openssh$"
                } |
                ForEach-Object -Begin { $newPath = '' } -Process { $newPath += "$_;" } -End { $newPath -replace ';;',';' })
                [Environment]::SetEnvironmentVariable('PATH',$env:PATH,[EnvironmentVariableTarget]::Machine)
            }

            # Download OpenSSH and move it to C:\OpenSSH
            $OpenSshDownloadUrl = $SSHReleaseMetadata.assets |
                Where-Object { $_.name -ieq 'OpenSSH-Win64.zip' } |
                Select-Object -ExpandProperty 'browser_download_url'

            $InstallPath = 'C:\OpenSSH'
            Write-Host "Downloading OpenSSH $($NewSshVersion.OpenSsshVersionString) from '$OpenSshDownloadUrl'..."
            DownloadAndExpandZipArchive -Url $OpenSshDownloadUrl -DestinationPath $env:TEMP
            Write-Host "Installing OpenSSH to $InstallPath..."
            Move-Item -Path (Join-Path $env:TEMP OpenSSH-Win64) -Destination $InstallPath -Force
            $SshAgentPath = Join-Path $InstallPath ssh-agent.exe
            $SshdPath = Join-Path $InstallPath sshd.exe
                    
            # The below is from install-sshd.ps1 which is now in C:\OpenSSH. We don't need SSHD set up,
            # we only want to replace ssh and ssh-agent (mainly ssh-agent). However, if SSHD is was originally
            # installed, then set it up, too.

            $etwmanifest = Join-Path $InstallPath openssh-events.man

            # Unregister ETW provider
            wevtutil um `"$etwmanifest`"

            [xml]$xml = Get-Content $etwmanifest
            $xml.instrumentationManifest.instrumentation.events.provider.resourceFileName = "$SshAgentPath"
            $xml.instrumentationManifest.instrumentation.events.provider.messageFileName = "$SshAgentPath"

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

            $SshAgentDesc = 'Agent to hold private keys used for public key authentication.'
            $null = New-Service -Name ssh-agent -DisplayName 'OpenSSH Authentication Agent' -Description $SshAgentDesc -BinaryPathName `"$sshagentpath`" -StartupType Automatic
            sc.exe sdset ssh-agent "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)"
            sc.exe privs ssh-agent SeImpersonatePrivilege
            if (!(Get-Service ssh-agent).Status -eq 'Running') {
                Start-Service ssh-agent
            }

            if ($Sshd) {
                $sshdDesc = 'SSH protocol based service to provide secure encrypted communications between two untrusted hosts over an insecure network.'
                $null = New-Service -Name sshd -DisplayName "OpenSSH SSH Server" -BinaryPathName `"$sshdpath`" -Description $sshdDesc -StartupType $SshdStartupType
                sc.exe privs sshd SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege

                if ($SshdIsRunning -and !(Get-Service sshd).Status -eq 'Running') {
                    Start-Service sshd -ErrorAction SilentlyContinue
                }
            }

            # !!! END install-sshd.ps1

            # Add C:\OpenSSH to the front of the PATH, so that this version is picked up over any other version that may appear later in PATH.
            if ($env:PATH -inotmatch 'C:\\OpenSSH') {
                $env:PATH = "C:\OpenSSH;$env:PATH"
                [Environment]::SetEnvironmentVariable('PATH', $env:PATH, [EnvironmentVariableTarget]::Machine)
            }
        } finally {
            Remove-Item (Join-Path $env:Temp OpenSSH-Win64) -Recurse -ErrorACtion SilentlyContinue
        }
    }
}

function Install-RancherWins {
    [CmdletBinding()]
    [OutputType([System.ServiceProcess.ServiceController])]
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
                $env:PATH = "$env:PATH;C:\wins" -replace ';;',';'
                [Environment]::SetEnvironmentVariable('PATH',$env:PATH,[EnvironmentVariableTarget]::Machine)
            }

            # Register wins as a service
            wins.exe srv app run --register

            $WinsSvc = Get-Service rancher-wins -ErrorAction Stop
        }

        $WinsSvc
    }
}

# TODO: Add parameters for the working directory...maybe other stuff...this cmdlet has A LOT of assumptions baked into it.....
function Join-KubernetesCluster {
    $Script:Config = Get-KubernetesWindowsNodeConfiguration

    $null = Import-Module .\hns.psm1 -WarningAction 'SilentlyContinue'

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

    $null = Install-RancherWins -Path $Script:WinsPath -Version $Script:Config.Wins.Version -ErrorAction Stop
    Write-Host "Rancher Wins has been installed as a Windows Service."
    Write-Host 'Starting Rancher Wins...'
    Start-Service rancher-wins

    $KubeletInstallArgs = @{
        KubeConfig = $env:KUBECONFIG
        KubeDnsServiceIpAddress = $Script:Config.Kubernetes.ControlPlain.DnsServiceIpAddress
    }
    if ($Script:Config.Kubernetes.Kubelet.FeatureGates) {
        $KubeletInstallArgs += @{ FeatureGates = $Script:Config.Kubernetes.Kubelet.FeatureGates }
    }
    $null = Install-Kubelet -ErrorAction Stop @InstallKubeletParams  @KubeletInstallArgs
    Write-Host "Installed Kubelet as a Windows Service"
    Write-Host 'Starting Kubelet...'
    Start-Service Kubelet -ErrorAction Stop

    kubeadm.exe join "$(Get-ApiServerEndpoint)" --token $Script:Config.Kubernetes.ControlPlane.JoinToken --discovery-token-ca-cert-hash "$($Script:Config.Kubernetes.ControlPlane.CAHash)"
    if (!$?) {
        Write-Error "Error joining cluster!"
        return
    }

    if (!(Test-NodeRunning)) {
        throw "Kubelet is not running and/or failed to bootstrap."
    }

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

        $Version = $GoLangVersionMetadata.Version

        if (!(docker images golang -q)) {
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

function New-KubernetesFlannelDaemonSetContainerImage {
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
                DownloadFile -Url ($FlannelDockerfile -replace 'Dockerfile$','setup.go') -Destination (Join-Path $pwd setup.go)

                # Get the latest version number/tag of yq from GitHub:
                $YqLatestReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/mikefarah/yq/releases/latest'
                $LatestYqVersion = $YqLatestReleaseMetadata.'tag_name'

                # Get the latest version number/tag of wins from GitHum:
                $WinsLatestReleaseMetadata = Invoke-RestMethod -Method GET -Uri 'https://api.github.com/repos/rancher/wins/releases/latest'
                $LatestWinsVersion = $WinsLatestReleaseMetadata.'tag_name'

                # Getting the dockerfile separately because we need to modify it...see below.
                $FlannelDockerfileContent = Invoke-RestMethod -Method Get -Uri $FlannelDockerfile

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

function New-KubernetesKubeProxyDaemonSetContainerImage {
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

        [string] $PauseImage,

        [string] $ServerCoreImage,

        [string] $WinsVersion = 'latest'
    )

    Process {
        $Script:Cwd = Get-Location
        $Script:WinVer = Get-WindowsBuildVersion

        # TODO: Set this in $env:TEMP??
        $WorkspacePath = "$env:SystemDrive\work"

        if (!(Test-Path $WorkspacePath)) {
            $null = New-Item -ItemType Directory -Path $WorkspacePath
        }

        try {
            Set-Location -Path $WorkspacePath
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
            $InfrastructureImages = [PSCustomObject]@{
                Build = $False
                Pause = 'mcr.microsoft.com/oss/kubernetes/pause:1.3.0'
            }

            if ($Script:WinVer -notmatch '^10\.0\.17763') {
                $InfrastructureImages.Build = $True
                $InfrastructureImages.PSObject.Properties.Remove('Pause');
                $InfrastructureImages |
                    Add-Member -MemberType NoteProperty -Name KubeProxyDockerfile -Value 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/kube-proxy/Dockerfile' -PassThru |
                    Add-Member -MemberType NoteProperty -Name PauseDockerfile -Value 'https://github.com/microsoft/SDN/raw/master/Kubernetes/windows/Dockerfile'

                if ($CniPluginName -ieq 'flannel') {
                    $InfrastructureImages | Add-Member -MemberType NoteProperty -Name FlannelDockerfile -Value 'https://github.com/kubernetes-sigs/sig-windws-tools/raw/master/kubeadm/flannel/Dockerfile'
                }
            } elseif ($CniPluginName -ieq 'flannel' -and (ShouldBuildCustomFlannelDockerContainerImage -FlannelVersion $CniPluginVersion.ToLower().TrimStart('v') -NetworkMode $NetworkMode)) {
                # If the requested version of flannel is not the same as the one being used in
                # the Windows DaemonSet at https://github.com/kubernetes-sigs/sig-windwos-tools,
                # then we must build the flannel image regardless of whether or not the base OS
                # version is the right version.
                #
                # For example, there's a known bug in Flannel 0.12.0 that's fixed in 0.13.0.
                # So this is one case why you'd want to "override" the image being used by the
                # DaemonSet.
                $InfrastructureImages.Build = $True
                $InfrastructureImages  | Add-Member -MemberType NoteProperty -Name FlannelDockerfile -Value 'https://github.com/kubernetes-sigs/sig-windows-tools/raw/master/kubeadm/flannel/Dockerfile'
            }

            $Script:Config = [PSCustomObject]@{
                PSTypeName = 'KubernetesWindowsNodeConfiguration'
                Cri = [PSCustomObject]@{
                    Name = $Cri
                }
                Cni = [PSCustomObject]@{
                    NetworkMode = $NetworkMode.ToLower()  # e.g. l2bridge, overlay
                    Version = $CniVersion.ToLower().TrimStart('v')
                    Plugin = [PSCustomObject]@{
                        Name = $CniPluginName          # e.g. flannel, kubenet
                        Version = $CniPluginVersion.ToLower().TrimStart('v')
                        WindowsDaemonSetUrl = $(if ($CniPluginName -ieq 'flannel') {
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
                        WindowsDaemonSetUrl = 'https://raw.githubusercontent.com/kubernetes-sigs/sig-windows-tools/master/kubeadm/kube-proxy/kube-proxy.yml'
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
                    Version = $(if ($WinsVersion -ne 'latest') { $WinsVersion.ToLower().TrimStart('v') } else { $WinsVersion })
                }
            }

            $Script:Config
        } finally {
            Set-Location $Script:Cwd
        }
    }
}

function New-WindowsKubernetesClusterNode {
    [CmdletBinding()]
    Param (
        [string] $ConfigurationFile,
        [string] $WorkspacePath = "$env:SystemDrive\work",
        [switch] $Force
    )

    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

    $Script:Cwd = Get-Location

    if (!(Test-Path $WorkspacePath)) {
        $null = New-Item -ItemType Directory -Path $WorkspacePath
    }

    try {
        Set-Location -Path $WorkspacePath

        LoadAndValidateKubernetesWindowsNodeConfiguration -Path $ConfigurationFile -Force:$Force -ErrorAction Stop
        Write-KubernetesWindowsNodeConfiguration $Script:Config

        ConfigureFirewall -Force:$Force

        $RequiresRestart = $False
        $RequiresRestart = Uninstall-WindowsDefenderFeature -Force:$Force
        $RequiresRestart = $RequireRestart -or (Install-ContainersFeature -Force:$Force)

        $SshExe = Get-Command ssh.exe -ErrorAction SilentlyContinue
        if ($SshExe.FileVersionInfo.FileVersionRaw -lt [Version]'8.1.0.0') {
            $RequiresRestart = Remove-WindowsOpenSSHCapability
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

        Install-ContainerRuntimeInterface -Name $Script:Config.Cri.Name -Force:$Force

        # >>>>> TODO: Get rid of this??
        Get-HnsScriptModule -Path $Pwd
        $null = Import-Module "$Pwd\hns.psm1" -DisableNameChecking

        Install-Nssm

        Install-PowerShellWin32OpenSSH

        SetupSshAccessToControlPlane -RemoteUser $Script:Config.Kubernetes.ControlPlane.Username -RemoteHost ($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+') -Force:$Force

        Get-KubernetesBinaries -Version $Script:Config.Kubernetes.Version -DestinationPath $Script:KubernetesClusterNodeInstallationPath -Force:$Force

        # >>>>>>>> TODO: DO WE NEED THIS??
        #Get-CniBinaries -Version $Script:Config.Cni.Version -NetworkMode $Script:Config.Cni.NetworkMode -PluginName $Script:Config.Cni.Plugin.Name -PluginVersion $Script:Config.Cni.Plugin.Version -Force:$Force

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
        $ShouldApplyClusterResources = !($Force -and $Force.IsPresent)
        if (!$Script:Config.Images.Infrastructure.Build) {
            if ($ShouldApplyClusterResources) {
                # Ask whether or not to go ahead and SCP them to the master control plane and apply them to the cluster.
                if (((Test-Path $env:USERPROFILE\.ssh\id_rsa) -or (Test-Path $env:USERPROFILE\.ssh\id_dsa)) -and "$(ssh-add.exe -L 2>$null)" -match "(?m)\s+$($env:USERPROFILE -replace '\\','\\')\\\.ssh\\id_[dr]sa$") {
                    $resp = Read-HostEx @"
If your SSH key has been authorized on the Linux Kubernetes master control plane node, do you want to copy the
Kubernetes Windows Pod resource configuration files to the master node and configure the Kubernetes cluster with them
in order to join this server to the cluster as a worker node? [Y|n] (Default 'Y') 
"@
                    if ($resp -ieq 'n') {
                        $ShouldApplyClusterResources = $False
                    }
                }

                if ($ApplyClusterResources) {
                    # Download the required YAML configuration files. kube-proxy.yml needs to me modified to denote which version
                    # of Kubernetes should be used. Then SCP them to the Linux control plane and apply them to the cluster via SSH.
                    @(
                        $Script:Config.Cni.Plugin.WindowsNodeConfigurationUrl,
                        $Script:Config.Kubernetes.KubeProxy.WindowsNodeConfigurationUrl
                    ) | ForEach-Object {
                        $OutFile = Split-Path $_ -Leaf
                        curl.exe -sL $_ -o $OutFile

                        if ($OutFile -imatch 'kube-proxy') {
                            (Get-Content $OutFile -Raw) -replace '(image: sigwindowstools/kube-proxy:)VERSION$',"`${1}v$($Script:Config.Kubernetes.Version)" |
                                Set-Content $OutFile
                        }

                        scp -o StrictHostKeyChecking=no $_ "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+'):~/$_"
                        ssh -T "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+')" kubectl apply -f $_
                    }
                }
            }
            
            if (!$ShouldApplyClusterResources) {
                Write-Warning @"

You MUST run the following commands on the $($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+') plane to configure the cluster for having this server
be a worker node:

    curl -sL https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/kube-proxy.yml | sed 's/VERSION/v$($Script:Config.Kubernetes.Version)/g' | kubectl apply -f -
    kubectl apply -f https://github.com/kubernetes-sigs/sig-windows-tools/releases/latest/download/flannel-$(if ($Script:Config.Cni.NetworkType -ieq 'overlay') { 'overlay' } else { 'host-gw' }).yml

"@
            }
        } else {
            # Otherwise, build custom networking container images and modify the YAML configuration files to use these
            # custom docker container images when the node is joined to the cluster.
            if ($Script:WinVer -notmatch '^10\.0\.17763') {
                Write-Host "The detected version of windows is v$Script:WinVer."
                Write-Host
                Write-Host "To setup this computer as a Kubernetes cluster node, custom docker container images are required because the current"
                Write-Host "version of Windows is not one of Windows Server LTSC2019 (1809) or 1903."
                Write-Host
                Write-Host "Docker on Windows requires that Windows-based Docker container images' base Windows operating system must match the host"
                Write-Host "operating system. Otherwise, the container will not start."
                Write-Host
            } elseif ($Script:Config.Images.Infrastructure.FlannelDockerfile) {
                $FlannelYml = Split-Path $Script:Config.Images.Infrastructure.FlannelDockerFile -Leaf
                Write-Host "The Windows Node Configuration metadata specifies that Flannel v$($Script:Config.Cni.Plugin.Version) should be used."
                Write-Host "However, $FlannelYml specifies a docker image using a different version of flannel."
                Write-Host
                Write-Host "A version of sigwindowstools/flannel with Flannel v$($Script:Config.Cni.Plugin.Version) will be built."
                Write-Host
            }

            if ($Script:Config.Images.Infrastructure.PauseDockerfile) {
                New-KubernetesPauseContainerImage $Script:Config.Images.Infrastructure.PauseDockerfile -Force:$Force -ErrorAction Stop
                Write-Host "Built custom Kubernetes infrastructure container image 'kubeletwin/pause'."
            }

            if ($Script:Config.Images.Infrastructure.FlannelDockerfile) {
                if ($Script:WinVer -notmatch '^10\.0\.17763') {
                    # There are limited versions of GoLang docker images. For example, there doesn't exist one
                    # for Windows 10.0.19041.508 (Windows Server 2019 2004).
                    #
                    # So in this case, build one so we can use it to build the flannel image.
                    $GoLangVersionMetadata = Get-GoLangVersionMetadata

                    New-GoLangContainerImage -GoLangVersionMetadata $GoLangVersionMetadata -Force:$Force -ErrorAction Stop
                    Write-Host "Built custom Golang docker container image."
                }

                $FlannelContainerImageParams = @{
                    GoLangDockerImageTag = "$($goLangVersionMetadata.Version)-windowsservercore-$Script:WinVer"
                    FlannelDockerfile = $Script:Config.Images.Infrastructure.FlannelDockerfile
                    FlannelVersion = $Script:Config.Cni.Plugin.Version
                    CniVersion = $Script:Config.Cni.Version
                    Force = $Force
                }
                New-KubernetesFlannelDaemonSetContainerImage -ErrorAction Stop @FlannelContainerImageParams
                Write-Host "Built custom Kubernetes Windows flannel docker container networking image."
            }

            if ($Script:Config.Images.Infrastructure.KubeProxyDockerfile) {
                New-KubernetesKubeProxyDaemonSetContainerImage -KubeProxyDockerfile $Script:Config.Images.Infrastructure.KubeProxyDockerfile -KubernetesVersion $Script:Config.Kubernetes.Version -Force:$Force -ErrorAction Stop
                Write-Host "Built custom Kubernetes kube-proxy docker container image."
            }

            # If we should apply the cluster resources, then as we download and modify the configuration files,
            # we'll transfer and apply them. Otherwise, after downloading and modifying, we'll display the required
            # commands to transfer and apply them BEFORE running Join-KubernetesCluster.
            if ($ShouldApplyClusterResources) {
                # Ask whether or not to go ahead and SCP them to the master control plane and apply them to the cluster.
                if (((Test-Path $env:USERPROFILE\.ssh\id_rsa) -or (Test-Path $env:USERPROFILE\.ssh\id_dsa)) -and "$(ssh-add.exe -L 2>$null)" -match "(?m)\s+$($env:USERPROFILE -replace '\\','\\')\\\.ssh\\id_[dr]sa$") {
                    $resp = Read-HostEx @"
If your SSH key has been authorized on the Linux Kubernetes master control plane node, do you want to copy the
Kubernetes Windows Pod resource configuration files to the master node and configure the Kubernetes cluster with them
in order to join this server to the cluster as a worker node? [Y|n] (Default 'Y') 
"@
                    if ($resp -ieq 'n') {
                        $ShouldApplyClusterResources = $False
                    }
                }
            }

            # No matter what, we want to pull down the YAML configuration files and modify them appropriately.
            @(
                $Script:Config.Cni.Plugin.WindowsDaemonSetUrl,
                $Script:Config.Kubernetes.KubeProxy.WindowsDaemonSetUrl
            ) | ForEach-Object {
                $ConfigurationUrl = $_
                $Outfile = Split-Path $_ -Leaf

                switch -regex ($Outfile) {
                    'flannel-(overlay|host-gw).yml' {
                        (Invoke-RestMethod -Method GET -Uri $ConfigurationUrl) `
                            -replace '(?m)sigwindowstools/flannel:\d+\.\d+\.\d+$', @"
kubeletwin/flannel:$($Script:Config.Cni.Plugin.Version)-windowsservercore-$Script:WinVer
        imagePullPolicy: Never
"@ | Set-Content $Outfile
                        break;
                    }
                    'kube-proxy.yml' {
                        (Invoke-RestMethod -Method GET -Uri $ConfigurationUrl) `
                            -replace '(?m)sigwindowstools/kube-proxy:VERSION$', @"
kubeletwin/kube-proxy:$($Script:Config.Kubernetes.Version)-windowsservercore-$Script:WinVer
        imagePullPolicy: Never
"@ | Set-Content $Outfile
                        break;
                    }
                }

                if ($ShouldApplyClusterResources) {
                    scp -o StrictHostKeyCHecking=no $(Join-Path $PWD $OutFile) "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+'):~/$OutFile"
                    ssh -T "$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+')" kubectl apply -f $OutFile
                }
            }

            if (!$ShouldApplyClusterResources) {
                Write-Warning @"

Either a SSH key was not detected or added to the SSH Agent, or you chose not to apply the cluster resource
configurations, or this script is being run non-interactively.

In order to properly configure the cluster to configure this Windows server as a worker node, please run the
following commands on this server BEFORE running Join-KubernetesCluster:

$(
    @(
        Split-Path $Script:Config.Cni.Plugin.WindowsDaemonSetUrl -Leaf
        Split-Path $Script:Config.Kubernetes.KubeProxy.WindowsDaemonSetUrl -Leaf
    ) | ForEach-Object {
        '    # Secure copy the cluster resource configuration file to the Linux master control plane'
        "    scp -o StrictHostKeyChecking=no $(Join-Path $PWD $_) `"$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+'):~/$_`"`n"
        "`n"
        '    # Using SSH, remotely execute a command on the Linux master control plane to apply the configuration'
        '    # to the cluster'
        "    ssh -T `"$($Script:Config.Kubernetes.ControlPlane.Username)@$($Script:Config.Kubernetes.ControlPlane.Address -replace ':\d+')`" kubectl apply -f $_"
    }
)


"@
            }
        }
        
        if (!($Force -and $Force.IsPresent)) {
            $resp = Read-HostEx "`n`nWould you like to join this server to the Kubernetes cluster now? [y/N] (Default 'N') " -ExpectedValue 'y','N'
            if ($resp -ieq 'Y') {
                Join-KubernetesCluster
            }
        } else {
            Write-Host 'When you''re ready to join this server to the Kubernetes cluster, plesee execute the following commands:'
            Write-Host
            Write-Host '    Import-Module KubernetesWindowsNodeHelpers.psm1'
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
        } elseif ($Response -and $ExpectedValue -and $Response -inotin $ExpectedValue) {
            Write-Host 'Invalid response. Please try again.'
        }
    } while ((!$Response -and $ValueRequired -and $ValueRequired.IsPresent) -or ($Response -and $ExpectedValue -and $Response -inotin $ExpectedValue))

    $Response
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

    Uninstall-KubeletService
    Uninstall-RancherWinsService
    Remove-KubernetesBinaries -Path $KubernetesClusterNodeInstallationPath
    Get-HnsNetwork | ? name -In 'vxlan0','flannel.4096' | Remove-HnsNetwork

    cmd /c rmdir /s /q c:\var  # <-- Remove-Item has a bug in PowerShell 5.1 where by -Recurse and -Force cause an error with symlinks
    Remove-Item $KubernetesClusterNodeInstallationPath -Recurse -ErrorAction SilentlyContinue -Force:$Force
    Remove-Item $env:USERPROFILE\.kube -Recurse -ErrorAction SilentlyContinue -Force:$Force
    Remove-Item C:\etc -Recurse -Force:$Force
    Remove-Item C:\run -Recurse -Force:$Force
}

function Remove-WindowsOpenSshCapability {
    [OutputType([boolean])] Param ()
    Process {
        # The SSH-Agent that ships with Windows only supports sending RSA SHA-1 signatures. OpenSSH considers SHA-1 to be too
        # weak (given it only costs ~$50K to collide SHA-1 hashes). So newer versions of SSH reject these hashes. Which all but
        # makes the version of ssh-agent that ships with Windows useless when interacting with Linux servers. This has been
        # "fixed" for 18-months, but not yet released. Since we can't wait, let's remove the built-in capability so that later
        # we can install and use the version the PowerShell team maintains (which eventually ends up in Windows anyway).
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

        $RequiresRestart
    }
}

function Set-KubernetesWindowsNodeConfiguration {
    [CmdletBinding()]
    [OutputType([Boolean])]
    Param (
        [Parameter(Position = 0)]
        [string] $Path = $Script:KubernetesClusterNodeConfigurationPath,

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

function Test-NodeRunning {
    kubectl.exe get nodes/$($env:COMPUTERNAME.ToLower())
    return !$LASTEXITCODE
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
        Version: $($Config.Cni.Version)
        Plugin:
            Name:                  $($Config.Cni.Plugin.Name)
            Version:               v$($Config.Cni.Plugin.Version)$(if ($Config.Cni.Plugin.Name -ieq 'flannel') { "
            Windows DaemonSet URL: $($Config.Cni.Plugin.WindowsDaemonSetUrl)" })
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
        Kubelet:
            FeatureGates: $($Config.Kubernetes.Kubelet.FeatureGates -join ', ')
        KubeProxy:
            FeatureGates:        $($Config.Kubernetes.KubeProxy.FeatureGates -join', ')
            WindowsDaemonSetUrl: $($Config.Kubernetes.KubeProxy.WindowsDaemonSetUrl)
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
[string] $Script:KubernetesClusterNodeInstallationPath = "$env:SystemDrive\k"
[string] $Script:KubernetesClusterNodeConfigurationPath = Join-Path $KubernetesClusterNodeInstallationPath '.kubewindowsnodeconfig'
[string] $Script:KubernetesClusterNodeLogPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'logs'
[string] $Script:CniPath = Join-Path $Script:KubernetesClusterNodeInstallationPath 'cni'
[string] $Script:CniConfigurationPath = Join-Path (Join-Path $Script:CniPath 'config') 'cni.conf'
[string] $Script:WinsPath = Join-Path $env:SystemDrive wins
