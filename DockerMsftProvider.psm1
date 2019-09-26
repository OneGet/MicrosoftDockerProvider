
#########################################################################################
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# DockerMsftProvider
#
#########################################################################################

#Requires -Version 5.0

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest

#region variables
$script:dockerProps = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property @{
                      pkgName="Docker"
                      pkgSources=@{};
                      pkgDefaultSourceName="DockerDefault";
                      pkgUrl="https://go.microsoft.com/fwlink/?LinkID=825636&clcid=0x409";
                      pkgServiceName="docker";
                      pathProgFilesPkgRoot="";
                      pathPkgServiceBin="";
                      pathPkgClientBin=""
                    }
$script:containerdProps = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property @{
                      pkgName="Containerd"
                      pkgSources=@{};
                      pkgDefaultSourceName="ContainerdDefault";
                      pkgUrl="https://onegetcontainerd.blob.core.windows.net/pkgs/containerd.json?sp=rl&st=2020-01-29T20:36:25Z&se=2025-01-30T20:36:00Z&sv=2019-02-02&sr=c&sig=77ibB37Lv4Ynl2OACOetZDdDjBI%2FInM5IZBkNqtNXmQ%3D";
                      pkgServiceName="containerd";
                      pathProgFilesPkgRoot="";
                      pathPkgServiceBin="";
                      pathPkgClientBin=""
                    }
$script:allAvailablePackages = @{
                 "docker" = $script:dockerProps
                 "containerd" = $script:containerdProps
                }

$packageProps = @()
$script:Providername = "DockerMsftProvider"
$script:DockerSources = $null
$script:location_modules = Microsoft.PowerShell.Management\Join-Path -Path $env:TEMP -ChildPath $script:ProviderName
$script:location_sources= Microsoft.PowerShell.Management\Join-Path -Path $env:LOCALAPPDATA -ChildPath $script:ProviderName
$script:file_modules = Microsoft.PowerShell.Management\Join-Path -Path $script:location_sources -ChildPath "sources.txt"
$script:DockerSearchIndex = "DockerSearchIndex.json"
$script:Installer_Extension = "zip"
$separator = "|#|"
$script:restartRequired = $false
$script:allPackages = $false
$script:isNanoServerInitialized = $false
$script:isNanoServer = $false
$script:SystemEnvironmentKey = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
$script:dummyName = "dummyName"
$script:pathProgFilesDummyNameRoot = Microsoft.PowerShell.Management\Join-Path -Path $env:ProgramFiles -ChildPath $script:dummyName
$script:pathProgFilesDockerRoot = Microsoft.PowerShell.Management\Join-Path -Path $env:ProgramFiles -ChildPath "docker"
$script:pathProgFilesContainerdRoot = Microsoft.PowerShell.Management\Join-Path -Path $script:pathProgFilesDockerRoot -ChildPath "containerd"
$script:pathDockerD = Microsoft.PowerShell.Management\Join-Path -Path $script:pathProgFilesDockerRoot -ChildPath "dockerd.exe"
$script:pathDockerClient = Microsoft.PowerShell.Management\Join-Path -Path $script:pathProgFilesDockerRoot -ChildPath "docker.exe"
$script:pathContainerd = Microsoft.PowerShell.Management\Join-Path -Path $script:pathProgFilesContainerdRoot -ChildPath "containerd.exe"
$script:wildcardOptions = [System.Management.Automation.WildcardOptions]::CultureInvariant -bor `
                          [System.Management.Automation.WildcardOptions]::IgnoreCase

$script:NuGetProviderName = "NuGet"
$script:NuGetBinaryProgramDataPath="$env:ProgramFiles\PackageManagement\ProviderAssemblies"
$script:NuGetBinaryLocalAppDataPath="$env:LOCALAPPDATA\PackageManagement\ProviderAssemblies"
$script:NuGetProvider = $null
$script:nanoserverPackageProvider = "NanoServerPackage"
$script:hotFixID = 'KB3176936'
$script:minOsMajorBuild = 14393
$script:minOSRevision= 206
$script:MetadataFileName = 'metadata.json'
$script:serviceName = "docker"
$script:SemVerTypeName = 'Microsoft.PackageManagement.Provider.Utility.SemanticVersion'
if('Microsoft.PackageManagement.NuGetProvider.SemanticVersion' -as [Type])
{
    $script:SemVerTypeName = 'Microsoft.PackageManagement.NuGetProvider.SemanticVersion'
}

$script:allAvailablePackages["docker"].pathProgFilesPkgRoot = $script:pathProgFilesDockerRoot
$script:allAvailablePackages["docker"].pathPkgServiceBin = $script:pathDockerD
$script:allAvailablePackages["docker"].pathPkgClientBin = $script:pathDockerClient
$script:allAvailablePackages["containerd"].pathProgFilesPkgRoot = $script:pathProgFilesContainerdRoot
$script:allAvailablePackages["containerd"].pathPkgServiceBin = $script:pathContainerd
$script:allAvailablePackages["containerd"].pathPkgClientBin = $script:pathContainerd
#endregion variables

#region One-Get Functions

function Find-Package
{
    [CmdletBinding()]
    param
    (
        [string[]]
        $names,

        [string]
        $RequiredVersion,

        [string]
        $MinimumVersion,

        [string]
        $MaximumVersion
    )

    Set-ModuleSourcesVariable
    $null = Install-NuGetClientBinary -CallerPSCmdlet $PSCmdlet

    $options = $request.Options

    foreach( $o in $options.Keys )
    {
        Write-Debug ( "OPTION: {0} => {1}" -f ($o, $options[$o]) )
    }

    $AllVersions = $null
    if($options.ContainsKey("AllVersions"))
    {
        $AllVersions = $options['AllVersions']
    }

    $sources = @()
    if($options.ContainsKey('Source'))
    {
        $sources = $options['Source']
    }

    if ((-not $names) -or ($names.Count -eq 0))
    {
        $names = "*"
    }

    $allPackages = @()
    $allResults = @()
    $allSources = Get-SourceList -Sources $sources

    foreach($currSource in $allSources)
    {
        foreach ($currPkg in $script:allAvailablePackages.Keys)
        {
            $currPkgName = $script:allAvailablePackages[$currPkg].pkgName

            # If the name of the current source starts with the current package name.......
            # (Note that neither of these two is a wildcard....)
            # then it should be considered........
            # as long as $names is *like* current package name.....
            if ($currSource.Name.StartsWith($currPkgName,"CurrentCultureIgnoreCase"))
            {
                if ($currPkgName -like $names)
                {
                    $Location = $currSource.SourceLocation
                    $sourceName = $currSource.Name
    
                    if($location.StartsWith("https://"))
                    {
                        $tempResults = @()
                        $tempResults += Find-FromUrl -Source $Location `
                                                        -SourceName $sourceName `
                                                        -Name $currPkgName `
                                                        -MinimumVersion $MinimumVersion `
                                                        -MaximumVersion $MaximumVersion `
                                                        -RequiredVersion $RequiredVersion `
                                                        -AllVersions:$AllVersions
    
                        if($tempResults)
                        {
                            $allResults += $tempResults
                        }
                    }
                    else
                    {
                        Write-Error "Currently only https sources are supported. Please register with https source."
                    }
                }

                break
            }
        }
    }

    if((-not $allResults) -or ($allResults.Count -eq 0))
    {
        return
    }

    foreach($result in $allResults)
    {
        $swid = New-SoftwareIdentityFromDockerInfo -DockerInfo $result
        Write-Output $swid
    }
}

function Download-Package
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FastPackageReference,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Location
    )

    DownloadPackageHelper -FastPackageReference $FastPackageReference `
                            -Request $Request `
                            -Location $Location
}

function Install-Helper-For-Docker
{
    param
    (
        [Parameter(Mandatory=$true)]
        [bool]
        $update,

        [Parameter(Mandatory=$true)]
        [bool]
        $force
    )

    if(Test-Path $script:pathDockerD)
    {
        if($update -or $force)
        {
            # Uninstall if another installation exists
            UninstallHelperForDocker
        }
        elseif(-not $force)
        {
            $dockerVersion = & "$script:pathDockerClient" --version
            $resultArr = $dockerVersion -split ","
            $version = ($resultArr[0].Trim() -split " ")[2]

            Write-Verbose "Docker $version already exists. Skipping install. Use -force to install anyway."
            return $false
        }
    }
    else
    {
        # Install WindowsFeature containers
        try
        {
            InstallContainer
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            ThrowError -CallerPSCmdlet $PSCmdlet `
                        -ExceptionName $_.Exception.GetType().FullName `
                        -ExceptionMessage $ErrorMessage `
                        -ErrorId FailedToDownload `
                        -ErrorCategory InvalidOperation

            return $false
        }        
    }

    return $true
}

function Install-Helper-For-Containerd
{
    param
    (
        [Parameter(Mandatory=$true)]
        [bool]
        $update,

        [Parameter(Mandatory=$true)]
        [bool]
        $force
    )

    if(Test-Path $script:pathContainerd)
    {
        if($update -or $force)
        {
            # Uninstall if another installation exists
            UninstallHelperForContainerd
        }
        elseif(-not $force)
        {
            $containerdVersion = & "$script:pathDockerClient" --version
            $resultArr = $containerdVersion -split ","
            $version = ($resultArr[0].Trim() -split " ")[2]

            Write-Verbose "Containerd $version already exists. Skipping install. Use -force to install anyway."
            return $false
        }
    }
    else
    {
        # Install WindowsFeature containers
        try
        {
            InstallContainer
        }
        catch
        {
            $ErrorMessage = $_.Exception.Message
            ThrowError -CallerPSCmdlet $PSCmdlet `
                        -ExceptionName $_.Exception.GetType().FullName `
                        -ExceptionMessage $ErrorMessage `
                        -ErrorId FailedToDownload `
                        -ErrorCategory InvalidOperation

            return $false
        }        
    }

    return $true
}

function Install-Package
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $fastPackageReference
    )

    if(-not (Test-AdminPrivilege))
    {
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName "InvalidOperationException" `
                    -ExceptionMessage "Administrator rights are required to install docker." `
                    -ErrorId "AdminPrivilegesAreRequiredForInstall" `
                    -ErrorCategory InvalidOperation
    }

    # The below checks hold true for both packages
    if(-not (IsNanoServer))
    {
        $osVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\').CurrentBuildNumber
        $osRevision = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\').UBR
        # Ensure that the host is either running a build newer than Windows Server 2016 GA or
        # if running Windows Server 2016 GA that it has a revision greater than 206 (KB3176936)
        if (($osVersion -lt $script:minOsMajorBuild) -or 
        (($osVersion -eq $script:minOsMajorBuild) -and ($osRevision -lt $script:minOsRevision)))
        {
            ThrowError -CallerPSCmdlet $PSCmdlet `
                        -ExceptionName "InvalidOperationException" `
                        -ExceptionMessage "$script:hotFixID or later is required for docker to work" `
                        -ErrorId "RequiredWindowsUpdateNotInstalled" `
                        -ErrorCategory InvalidOperation
            return
        }
    }
    else
    {
        Write-Warning "$script:hotFixID or later is required for docker to work. Please ensure this is installed."
    }

    $options = $request.Options
    $update = $false
    $force = $false

    if($options)
    {
        foreach( $o in $options.Keys )
        {
            Write-Debug ("OPTION: {0} => {1}" -f ($o, $request.Options[$o]) )
        }

        if($options.ContainsKey('Update'))
        {
            Write-Verbose "Updating the installation."
            $update = $true
        }

        if($options.ContainsKey("Force"))
        {
            $force = $true
        }
    }

    $splitterArray = @("$separator")
    $resultArray = $fastPackageReference.Split($splitterArray, [System.StringSplitOptions]::None)

    if((-not $resultArray) -or ($resultArray.count -ne 8)){Write-Debug "Fast package reference doesn't have required parts."}

    $source = $resultArray[0]
    $name = $resultArray[1]
    $version = $resultArray[2]
    $description = $resultArray[3]
    $originPath = $resultArray[5]
    $size = $resultArray[6]
    $sha = $resultArray[7]
    $date = $resultArray[4]
    $Location = $script:location_modules

    $destination = GenerateFullPath -Location $Location `
                                    -Name $name `
                                    -Version $Version

    $downloadOutput = DownloadPackageHelper -FastPackageReference $FastPackageReference `
                            -Request $Request `
                            -Location $Location

    if(-not (Test-Path $destination))
    {
        Write-Error "$destination does not exist"
        return 
    }
    else
    {
        Write-verbose "Found $destination to install."
    }

    if ($name -like "docker")
    {
        $cont = Install-Helper-For-Docker -update $update -force $force 
        $name = "docker"
    }
    elseif ($name -like "containerd")
    {
        $cont = Install-Helper-For-Containerd -update $update -force $force 
        $name = "containerd"
    }
    else
    {
        return
    }

    # Install
    try 
    {
        Write-Verbose "Trying to unzip : $destination"
        $null = Expand-Archive -Path $destination -DestinationPath $env:temp -Force

        # Now copy the files into the destinatipon folder.
        if($name -like "docker")
        {
            $script:pathTempDockerRoot = Microsoft.PowerShell.Management\Join-Path -Path $env:temp -ChildPath "docker"

            if (-not (Test-Path $script:pathProgFilesDockerRoot)) {$null = mkdir $script:pathProgFilesDockerRoot}
            $null = Get-ChildItem -Path $script:pathTempDockerRoot| Where-Object { $_.Name -ne 'containerd'}|Copy-Item -Destination $script:pathProgFilesDockerRoot -force -Recurse
        
            $null = Rename-Item -Path $script:pathProgFilesDockerRoot -NewName $script:dummyName
            $null = Rename-Item -Path $env:ProgramFiles\$script:dummyName -NewName "docker"

            $serviceBinPath = $script:pathDockerD
        }
        elseif($name -like "containerd")
        {
            $script:pathTempContainerdRoot = Microsoft.PowerShell.Management\Join-Path -Path $env:temp -ChildPath "Containerd"
            if (-not (Test-Path $script:pathProgFilesContainerdRoot)) {$null = mkdir $script:pathProgFilesContainerdRoot}
            $null = Get-ChildItem -Path $script:pathTempContainerdRoot| Copy-Item -Destination $script:pathProgFilesContainerdRoot -force -Recurse
        
            $null = Rename-Item -Path $script:pathProgFilesContainerdRoot -NewName $script:dummyName
            $null = Rename-Item -Path $script:pathProgFilesDockerRoot\$script:dummyName -NewName "containerd"

            $serviceBinPath = $script:pathContainerd
        }

        if(Test-Path $serviceBinPath)
        {
            Write-Verbose "Trying to enable the service..."
            $service = get-service -Name $name -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            if(-not $service)
            {
                & "$serviceBinPath" --register-service
            }
        }
        else
        {
            Write-Error "Unable to expand to Program Files."
        }
    }
    catch
    {
        $ErrorMessage = $_.Exception.Message
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName $_.Exception.GetType().FullName `
                    -ExceptionMessage $ErrorMessage `
                    -ErrorId FailedToDownload `
                    -ErrorCategory InvalidOperation
    }
    finally
    {
        # Clean up
        Write-Verbose "Removing the archive: $destination"
        $null = remove-item $destination -Force
    }

    # Save the install information
    $null = SaveInfo -Source $source -PkgName $name

    # Update the path variable
    $null = Update-PathVar -pkgName $name

    if($script:restartRequired)
    {
        Write-Warning "A restart is required to enable the containers feature. Please restart your machine."
    }

    Write-Output $downloadOutput
}

function Uninstall-Package
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $fastPackageReference
    )

    [string[]] $splitterArray = @("$separator")
    [string[]] $resultArray = $fastPackageReference.Split($splitterArray, [System.StringSplitOptions]::None)

    if((-not $resultArray) -or ($resultArray.count -ne 3)){Write-Debug "Fast package reference doesn't have required parts."}

    # Find-Package and Get-Package deliver the components in a different sequence and we need to support both so....
    $source = $resultArray[0]
    $name = $resultArray[1]
    $version = $resultArray[2]

    if (-not ($name -like "docker" -or $name -like "containerd"))
    {
        $name = $resultArray[0]
        $version = $resultArray[1]
        $source = $resultArray[2]
    }

    if ($name -like "docker")
    {
        UninstallHelperForDocker

        Write-Verbose "Uninstalling container feature from windows"
        #UninstallContainer
    }
    elseif ($name -like "containerd")
    {
        UninstallHelperForContainerd
    }

    $dockerSWID = @{
            Name = $name
            version = $version
            Source = $source
            versionScheme = "MultiPartNumeric"
            fastPackageReference = $fastPackageReference
    }

    New-SoftwareIdentity @dockerSWID
}

#endregion One-Get Functions

#region One-Get Required Functions

function Initialize-Provider
{
    write-debug "In $($script:Providername) - Initialize-Provider"
}

function Get-PackageProviderName
{
    return $script:Providername
}

function Get-InstalledPackage
{
    param
    (
        [string]$name,
        [string]$requiredVersion,
        [string]$minimumVersion,
        [string]$maximumVersion
    )

    if(-not $name)
    {
        $name = "*"
    }

    $ret = @();

    foreach ($currPkg in $script:allAvailablePackages.Keys)
    {
        $currPkgName = $script:allAvailablePackages[$currPkg].pkgName

        $version = ''
        $source = ''
        
        # If the name of the current source starts with the current package name.......
        # (Note that neither of these two is a wildcard....)
        # then it should be considered........
        # as long as $names is *like* current package name.....
        if ($currPkgName -like $name)
        {
            $currPkgRoot = $script:allAvailablePackages[$currPkgName].pathProgFilesPkgRoot

            if(Test-Path $currPkgRoot\$script:MetadataFileName) 
            {
                $metaContent = (Get-Content -Path $currPkgRoot\$script:MetadataFileName)

                if(IsNanoServer)
                {
                    $jsonDll = [Microsoft.PowerShell.CoreCLR.AssemblyExtensions]::LoadFrom($PSScriptRoot + "\Json.coreclr.dll")
                    $jsonParser = $jsonDll.GetTypes() | Where-Object name -match jsonparser
                    $metaContentParsed = $jsonParser::FromJson($metaContent)

                    $source = if($metaContentParsed.ContainsKey('SourceName')) {$metaContentParsed.SourceName} else {'Unable To Retrieve Source from metadata.json'}
                    $version = if($metaContentParsed.ContainsKey('Version')) {$metaContentParsed.Version} else {'Unable To Retrieve Version from metadata.json'}
                }
                else
                {
                    $metaContentParsed = (Get-Content -Path $currPkgRoot\$script:MetadataFileName) | ConvertFrom-Json
                    if($metaContentParsed)
                    {
                        $source = if($metaContentParsed.PSObject.properties.name -contains 'SourceName') {$metaContentParsed.SourceName} else {'Unable To Retrieve Source from metadata.json'}
                        $version = if($metaContentParsed.PSObject.properties.name -contains 'Version') {$metaContentParsed.Version} else {'Unable To Retrieve Version from metadata.json'}
                    }            
                }
            }
            elseif(Test-Path $script:allAvailablePackages[$currPkgName].pathPkgServiceBin)
            {
                $pkgClientBin = $script:allAvailablePackages[$currPkgName].pathPkgClientBin
                $obtainedVersion = & $pkgClientBin --version
                $resultArr = $obtainedVersion -split ","
                $version = ($resultArr[0].Trim() -split " ")[2]
                $source = ' '
            }

            if ($version -ne '')
            {
                $fastPackageReference = $currPkgName +
                                    $separator + $version +
                                    $separator + $source

                $resultSWID = @{
                                Name = $currPkgName
                                version = $version
                                Source = $source
                                #versionScheme = "MultiPartNumeric"
                                versionScheme = "Alphanumeric"
                                fastPackageReference = $fastPackageReference
                                }

                $tmp = New-SoftwareIdentity @resultSWID 
                $ret += $tmp
            }
        }
    }

    return $ret
}

#endregion One-Get Required Functions

#region Helper-Functions

function SaveInfo
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Source,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PkgName
    )

    # Create a file
    $metaFileInfo = New-Item -ItemType File -Path $script:allAvailablePackages[$PkgName].pathProgFilesPkgRoot -Name $script:MetadataFileName -Force

    if(-not $metaFileInfo)
    {
        # TODO: Handle File not created scenario
    }

    $pathPkgServiceBin = $script:allAvailablePackages[$PkgName].pathPkgServiceBin
    if(Test-Path $pathPkgServiceBin)
    {
        $serviceVer = & "$pathPkgServiceBin" --version
        $resultArr = $serviceVer -split ","
        $version = ($resultArr[0].Trim() -split " ")[2]

        $metaInfo = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property ([ordered]@{
            SourceName = $source
            Version = $version 
        })

        $metaInfo | ConvertTo-Json > $metaFileInfo
    }
}

function Uninstall-CommonTasks
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $serviceName,

        [Parameter(Mandatory=$true)]
        [String]
        $serviceBinPath
    )

    if(-not (Test-AdminPrivilege))
    {
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName "InvalidOperationException" `
                    -ExceptionMessage "Administrator rights are required to install $serviceName." `
                    -ErrorId "AdminPrivilegesAreRequiredForInstall" `
                    -ErrorCategory InvalidOperation
    }

    # Stop service
    $Service = get-service -Name $serviceName -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if(-not $Service)
    {
        # Service is not available
        Write-Warning "$serviceName Service is not available."
        return
    }

    if(($Service.Status -eq "Started") -or ($Service.Status -eq "Running"))
    {
        Write-Verbose "Trying to stop $serviceName service"
        $null = stop-service $serviceName
    }

    if(Test-Path $serviceBinPath)
    {
        Write-Verbose "Unregistering the service"
        $null = & "$serviceBinPath" --unregister-service
    }
    else
    {
        Write-Warning "$serviceBinPath is not present under the Program Files. Please check the installation."
    }
}
        
function UninstallHelperForDocker
{
    Uninstall-CommonTasks -serviceName "docker" -serviceBinPath $script:pathDockerD

    if(Test-Path $script:pathDockerD)
    {
        Write-Verbose "Removing the docker files"
        
        # Avoid rewriting or removing the containerd files
        $null = Get-ChildItem -ad -Path $script:pathProgFilesDockerRoot| Where-Object { $_.Name -ne 'containerd'}|Remove-Item -force -Recurse
        $null = Get-ChildItem -af -Path $script:pathProgFilesDockerRoot| Remove-Item -force -Recurse

        if((Test-Path $script:pathProgFilesDockerRoot) -and (-not (Test-Path $script:pathProgFilesContainerdRoot))) {$null = Remove-Item $script:pathProgFilesDockerRoot -Force}
    }
    else
    {
        Write-Warning "Docker is not present under the Program Files. Please check the installation."
    }

    Write-Verbose "Removing the path variable"
    $null = Remove-PathVar -pkgName "docker"
}

function UninstallHelperForContainerd
{
    Uninstall-CommonTasks -serviceName "containerd" -serviceBinPath $script:pathContainerd

    if(Test-Path $script:pathContainerd)
    {
        Write-Verbose "Removing the containerd files"
        
        $null = Get-ChildItem -Path $script:pathProgFilesContainerdRoot| Remove-Item -force -Recurse

        $null = Remove-Item $script:pathProgFilesContainerdRoot -Force

        $directoryInfo = Get-ChildItem $script:pathProgFilesDockerRoot | Measure-Object
        if($directoryInfo.count -eq 0) {$null = Remove-Item $script:pathProgFilesDockerRoot -Force}
    }
    else 
    {
        Write-Warning "Containerd is not present under the Program Files. Please check the installation."
    }

    Write-Verbose "Removing the path variable"
    $null = Remove-PathVar -pkgName "containerd"
}

function InstallContainer
{
    if(IsNanoServer)
    {        
        if(HandleProvider)
        {
            $containerExists = get-package -providername NanoServerPackage -Name *container* -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

            if($containerExists)
            {
                Write-Verbose "Containers package is already installed. Skipping the install."
                return
            }

            # Find Container Package
            $containerPackage = Find-NanoServerPackage -Name *Container* -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

            if(-not $containerPackage)
            {
                ThrowError -ExceptionName "System.ArgumentException" `
                            -ExceptionMessage "Unable to find the Containers Package from NanoServerPackage Module." `
                            -ErrorId "PackageNotFound" `
                            -CallerPSCmdlet $PSCmdlet `
                            -ErrorCategory InvalidOperation
            }

            Write-Verbose "Installing Containers..."
            $null = $containerPackage | Install-NanoServerPackage -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            $script:restartRequired = $true
        }
        else
        {
            ThrowError -ExceptionName "System.ArgumentException" `
                            -ExceptionMessage "Unable to load the NanoServerPackage Module." `
                            -ErrorId "ModuleNotFound" `
                            -CallerPSCmdlet $PSCmdlet `
                            -ErrorCategory InvalidOperation
        }
    }
    else
    {
        switch(Get-wmiobject -class win32_operatingsystem | select-object -ExpandProperty Caption ){                
            'Microsoft Windows 10' {
                $containerExists = Get-WindowsOptionalFeature -Online -FeatureName Containers | 
                Select-object -Property *,@{name='Installed';expression={$_.State -eq 'Enabled'}}
            }
            Default {$containerExists = Get-WindowsFeature -Name Containers}
        }
        if($containerExists -and $containerExists.Installed)
        {
            Write-Verbose "Containers feature is already installed. Skipping the install."
            return
        }
        else
        {
            Write-Verbose "Installing Containers..."
            switch(Get-wmiobject -class win32_operatingsystem | select-object -ExpandProperty Caption ){                
                'Microsoft Windows 10' {$null = Enable-WindowsOptionalFeature -FeatureName Containers}
                Default {$null = Install-WindowsFeature containers}
            }
            $script:restartRequired = $true            
        }
    }

    Write-Verbose "Installed containers"
}

function UninstallContainer
{
    if(IsNanoServer)
    {
        return
    }
    else
    {
        switch(Get-wmiobject -class win32_operatingsystem | select-object -ExpandProperty Caption ){
            'Microsoft Windows 10' {$null = Disable-WindowsOptionalFeature -FeatureName Containers}
            Default {$null = Uninstall-WindowsFeature containers        }
        }
        
    }
}

function HandleProvider
{
    # Get the nanoServerpackage provider is present
    $getnanoServerPackage = Get-PackageProvider -Name $script:nanoserverPackageProvider -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    # if not download and install
    if(-not $getnanoServerPackage)
    {
        $repositories = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if(-not $repositories){$null = Register-PSRepository -Default}

        $nanoserverPackage = Find-Module -Name $script:nanoserverPackageProvider -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Repository PSGallery
        if(-not $nanoserverPackage)
        {
            ThrowError -ExceptionName "System.ArgumentException" `
                        -ExceptionMessage "Unable to find the Containers Package from NanoServerPackage Module." `
                        -ErrorId "PackageNotFound" `
                        -CallerPSCmdlet $PSCmdlet `
                        -ErrorCategory InvalidOperation
        }

        # Install the provider 
        $null = $nanoserverPackage | Install-Module -Force -SkipPublisherCheck
    }
    
    # Import the provider
    $importProvider = Import-PackageProvider -Name $script:nanoserverPackageProvider -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    $importModule = Import-module -Name $script:nanoserverPackageProvider -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -PassThru

    return ($importModule -and $importProvider)
}

function Update-PathVar
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $pkgName
    )

    if ($pkgName -like "docker")
    {
        $pathProgFilesRootToAdd = $script:pathProgFilesDockerRoot 
    }
    elseif ($pkgName -like "containerd")
    {
        $pathProgFilesRootToAdd = $script:pathProgFilesContainerdRoot 
    }

    $NameOfPath = "Path"

    # Set the environment variable in the Local Process
    $envVars = [Environment]::GetEnvironmentVariable($NameOfPath)
    $envArr = @()
    $envArr = $envVars -split ';'
    $envFlag = $true
    foreach($envItem in $envArr) 
    {
        if($envItem.Trim() -match [regex]::Escape($pathProgFilesRootToAdd)) 
        {
            if ($envItem.Trim().length -eq $pathProgFilesRootToAdd.length)
            {
                $envFlag = $false
                break
            }
        }
    }
    if($envFlag)
    {
        $null = [Environment]::SetEnvironmentVariable($NameOfPath, $envVars + ";" + $pathProgFilesRootToAdd)
    }

    # Set the environment variable in the Machine
    $currPath = (Microsoft.PowerShell.Management\Get-ItemProperty -Path $script:SystemEnvironmentKey -Name $NameOfPath -ErrorAction SilentlyContinue).Path    
    $currArr = @()
    $currArr = $currPath -split ';'
    $currFlag = $true
    foreach($currItem in $currArr)
    {
        if($currItem.Trim() -match [regex]::Escape($pathProgFilesRootToAdd)) 
        {
            if ($currItem.Trim().length -eq $pathProgFilesRootToAdd.length)
            {
                $currFlag = $false
                break
            }
        }
    }
    if($currFlag)
    {
        $null = Microsoft.PowerShell.Management\Set-ItemProperty $script:SystemEnvironmentKey -Name $NameOfPath -Value ($currPath + ";" + $pathProgFilesRootToAdd)

        # Nanoserver needs a reboot to persist the registry change
        if(IsNanoServer)
        {
            $script:restartRequired = $true
        }        
    }
}

function Remove-PathVar
{
    param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $pkgName
    )

    if ($pkgName -like "docker")
    {
        $pathProgFilesRootToRemove = $script:pathProgFilesDockerRoot 
    }
    elseif ($pkgName -like "containerd")
    {
        $pathProgFilesRootToRemove = $script:pathProgFilesContainerdRoot 
    }

    $NameOfPath = "Path"

    # Set the environment variable in the Local Process
    $envVars = [Environment]::GetEnvironmentVariable($NameOfPath)
    $envArr = @()
    $envArr = $envVars -split ';'
    $envFlag = $false
    $newPath = ""
    foreach($envItem in $envArr) 
    {
        if(($envItem.Trim() -match [regex]::Escape($pathProgFilesRootToRemove)) -and ($envItem.Trim().length -eq $pathProgFilesRootToRemove.length))
        {
            $envFlag = $true
        }
        else
        {
            if ($newPath -eq "")
            {
                $newPath = $envItem
            }
            else
            {
                $newPath = $newPath + ";" + $envItem
            }
        }
    }
    if($envFlag)
    {
        $null = [Environment]::SetEnvironmentVariable($NameOfPath, $newPath)
    }

    # Set the environment variable in the Machine
    $currPath = (Microsoft.PowerShell.Management\Get-ItemProperty -Path $script:SystemEnvironmentKey -Name $NameOfPath -ErrorAction SilentlyContinue).Path
    $currArr = @()
    $currArr = $currPath -split ';'
    $newPath = ""
    $currFlag = $false
    foreach($currItem in $currArr)
    {
        if(($currItem.Trim() -match [regex]::Escape($pathProgFilesRootToRemove)) -and ($currItem.Trim().length -eq $pathProgFilesRootToRemove.length))
        {
            $currFlag = $true
        }
        else
        {
            if ($newPath -eq "")
            {
                $newPath = $currItem
            }
            else
            {
                $newPath = $newPath + ";" + $currItem
            }
        }
    }
    if($currFlag)
    {
        $null = Microsoft.PowerShell.Management\Set-ItemProperty $script:SystemEnvironmentKey -Name $NameOfPath -Value $newPath
    }
}


function DeSerialize-PSObject
{
    [CmdletBinding(PositionalBinding=$false)]
    Param
    (
        [Parameter(Mandatory=$true)]        
        $Path
    )
    $filecontent = Microsoft.PowerShell.Management\Get-Content -Path $Path
    [System.Management.Automation.PSSerializer]::Deserialize($filecontent)    
}

function Save-ModuleSources
{
    param
    (
        [Parameter(Mandatory=$true)]
        [psobject]
        $sourceToSave,

        [Parameter(Mandatory=$true)]
        [String]
        $filePathToSaveTo
    )

    if(-not (Test-Path $script:location_sources))
    {
        $null = mkdir $script:location_sources
    }

    Microsoft.PowerShell.Utility\Out-File -FilePath $filePathToSaveTo `
                                          -Force `
                                          -InputObject ([System.Management.Automation.PSSerializer]::Serialize($sourceToSave))

}

function Get-SourceList
{
    param
    (
        [Parameter(Mandatory=$true)]        
        $sources
    )

    Set-ModuleSourcesVariable

    $listOfSources = @()
    
    foreach ($curPkg in $script:allAvailablePackages.Keys)
    {
        $curPkgSources = $script:allAvailablePackages[$curPkg].pkgSources

        foreach($mySource in $curPkgSources.Values)
        {
            if((-not $sources) -or
                (($mySource.Name -eq $sources) -or
                   ($mySource.SourceLocation -eq $sources)))
            {
                $tempHolder = @{}
    
                $location = $mySource."SourceLocation"
                $tempHolder.Add("SourceLocation", $location)
                
                $packageSourceName = $mySource.Name
                $tempHolder.Add("Name", $packageSourceName)
                
                $listOfSources += $tempHolder
            }
        }
    }

    return $listOfSources
}

function Resolve-ChannelAlias
{
    param
    (
        [Parameter(Mandatory=$true)]
        [psobject]
        $Channels,

        [Parameter(Mandatory=$true)]
        [String]
        $Channel
    )

    while ($Channels.$Channel.PSObject.Properties.Name -contains 'alias')
    {
        $Channel = $Channels.$Channel.alias
    }

    return $Channel
}

function Find-FromUrl
{
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Uri]
        $Source,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SourceName,

        [Parameter(Mandatory=$false)]
        [String]
        $Name,

        [Parameter(Mandatory=$false)]
        [String]
        $MinimumVersion,

        [Parameter(Mandatory=$false)]
        [String]
        $MaximumVersion,
        
        [Parameter(Mandatory=$false)]
        [String]
        $RequiredVersion,

        [Parameter(Mandatory=$false)]
        [switch]
        $AllVersions
    )

    if(('docker' -ne $Name) -and ('containerd' -ne $Name)) {return $Null}

    # Match only appropriate sources for the package.....
    if (-Not (('docker' -like $Name -and $SourceName.StartsWith('docker',"CurrentCultureIgnoreCase")) -or
        ('containerd' -like $Name -and $SourceName.StartsWith('containerd',"CurrentCultureIgnoreCase"))))
    {
        return $null
    }

    $searchFile = Get-SearchIndex -fwdLink $Location `
                                    -SourceName $SourceName

    [String] $searchFileContent = Get-Content -Path $searchFile

    if(-not $searchFileContent)
    {
        return $null
    }

    $updatedContent = $searchFileContent.Trim(" .-`t`n`r")
    $contents = $updatedContent | ConvertFrom-Json
    $channels = $contents.channels
    $versions = $contents.versions
    $channelValues = $channels | Get-Member -MemberType NoteProperty
    $searchResults = @()

    # Set the default channel, allowing $RequiredVersion to override when set to a channel name.
    $defaultChannel = 'cs'
    if ($RequiredVersion)
    {
        foreach ($channel in $channelValues)
        {
            if ($RequiredVersion -eq $channel.Name)
            {
                $defaultChannel = $channel.Name
                $RequiredVersion = $null
                break
            }
        }
    }

    # if no versions are mentioned, just provide the default version, i.e.: CS 
    if((-not ($MinimumVersion -or $MaximumVersion -or $RequiredVersion -or $AllVersions)))
    {
        $resolvedChannel = Resolve-ChannelAlias -Channels $channels -Channel $defaultChannel
        $RequiredVersion = $channels.$resolvedChannel.version
    }

    # if a particular version is requested, provide that version only
    if($RequiredVersion)
    {
        if($versions.PSObject.properties.name -contains $RequiredVersion)
        {
            $obj = Get-ResultObject -JSON $versions -Version $RequiredVersion -PkgName $Name
            $searchResults += $obj
            return $searchResults
        }
        else {
            return $null
        }
    }

    $savedVersion = New-Object $script:SemVerTypeName -ArgumentList '0.0.0'
    
    if($MinimumVersion)
    {
        $convertedMinimumVersion =  New-Object $script:SemVerTypeName -ArgumentList $MinimumVersion
    }

    if($MaximumVersion)
    {
        $convertedMaximumVersion =  New-Object $script:SemVerTypeName -ArgumentList $MaximumVersion
    }


    # version requirements
    # compare different versions
    foreach($channel in $channelValues)
    {
        if ($channel.Name -eq $defaultChannel)
        {
            continue
        }
        else 
        {
            $versionName = Resolve-ChannelAlias -Channels $channels -Channel $channel.Name
            $versionValue = $channels.$versionName.version
            $thisVersion = New-Object $script:SemVerTypeName -ArgumentList $versionValue

            if(($MinimumVersion -and ($thisVersion -lt $convertedMinimumVersion)) -or 
               ($MaximumVersion -and ($thisVersion -gt $convertedMaximumVersion)))
            {
                continue
            }

            if($thisVersion -ge $savedVersion) {$savedVersion = $thisVersion}

            if($AllVersions)
            {
                $obj = Get-ResultObject -JSON $versions -Version $versionValue -PkgName "ss2"
                $searchResults += $obj
            }
        }
    }

    # so that we do not include twice for $AllVersions....
    if(-not $AllVersions)
    {
        if($savedVersion -eq '0.0.0'){return $null}

        $ver = $savedVersion.ToString()
        $obj = Get-ResultObject -JSON $versions -Version $ver -PkgName "ss3"
        $searchResults += $obj
    }

    return $searchResults
}

function Get-ResultObject
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $PkgName,

        [Parameter(Mandatory=$true)]
        [string]
        $Version,

        [Parameter(Mandatory=$true)]
        [psobject]
        $JSON
    )

    if($JSON.$Version)
    {   
        $description = ""
        if($versions.$Version.Psobject.properties.name -contains "notes")
        {
            $URL = $versions.$Version.'notes'
            if($URL.StartsWith("https://"))
            {
                try
                {
                    $description = (Invoke-WebRequest -Uri $URL).Content
                }
                catch
                {
                    Write-verbose "Bad URL provided for description: $URL"
                }
            }
            else
            {
                $description = $versions.$Version.'notes'
            }
        }

        $obj = $versions.$Version.PSObject.Copy()
        $null = $obj | Add-Member NoteProperty Version $Version
        $null = $obj | Add-Member NoteProperty Name $PkgName
        $null = $obj | Add-Member NoteProperty SourceName $SourceName
        $null = $obj | Add-Member NoteProperty Description $description

        return $obj
    }
    
    return $null
}

function Get-SearchIndex
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]
        $fwdLink,

        [Parameter(Mandatory=$true)]
        [string]
        $SourceName
    )

    $fullUrl = Resolve-FwdLink $fwdLink
    $searchIndex = $SourceName + "_" + $script:DockerSearchIndex
    $destination = Join-Path $script:location_modules $searchIndex

    if(-not(Test-Path $script:location_modules))
    {
        $null = mkdir $script:location_modules
    }

    if(Test-Path $destination)
    {
        $null = Remove-Item $destination
        $null = DownloadFile -downloadURL $fullUrl `
                    -destination $destination
    }
    else
    {
        $null = DownloadFile -downloadURL $fullUrl `
                    -destination $destination
    }
    
    return $destination
}

function Resolve-FwdLink
{
    param
    (
        [parameter(Mandatory=$false)]
        [System.String]$Uri
    )
    
    $response = Get-HttpResponse -Uri $Uri

    if(-not $response)
    {
        # This is not a forward link. Return the original URI
        return $Uri
    }

    $link = $response.Result.RequestMessage.RequestUri
    $fullUrl = $link.AbsoluteUri
    return $fullUrl
}

function Get-HttpResponse
{
    param
    (
        [Parameter(Mandatory=$false)]
        [System.String]
        $Uri
    )

    if(-not (IsNanoServer))
    {
        Add-Type -AssemblyName System.Net.Http
    }

    $httpClient = New-Object System.Net.Http.HttpClient
    $response = $httpclient.GetAsync($Uri)

    return $response
}

function New-SoftwareIdentityFromDockerInfo
{
    param
    (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]
        $DockerInfo
    )

    $fastPackageReference = $DockerInfo.SourceName +
                                $separator + $DockerInfo.Name + 
                                $separator + $DockerInfo.Version + 
                                $separator + $DockerInfo.Description  +
                                $separator + $dockerInfo.date +
                                $separator + $dockerInfo.url  +
                                $separator + $dockerInfo.size +
                                $separator + $dockerInfo.sha256
    
    $params = @{
                    FastPackageReference = $fastPackageReference;
                    Name = $DockerInfo.Name;
                    Version = $DockerInfo.Version;
                    Source = $DockerInfo.SourceName;
                    versionScheme  = "MultiPartNumeric";
                    Summary = $DockerInfo.Description;                    
                }

    New-SoftwareIdentity @params
}

function Set-ModuleSourcesVariable
{
    [CmdletBinding()]
    param([switch]$Force)

    #Iterate over all packages.....
    foreach ($curPkg in $script:allAvailablePackages.Keys)
    {
        $curPkgPersistFile = $script:allAvailablePackages[$curPkg].pkgServiceName + "sources.txt"
        $curPkgPersistFilePath = Microsoft.PowerShell.Management\Join-Path -Path $script:location_sources -ChildPath $curPkgPersistFile 

        $curPkgDefaultSourceName = $script:allAvailablePackages[$curPkg].pkgDefaultSourceName
        if(Microsoft.PowerShell.Management\Test-Path $curPkgPersistFilePath)
        {
            $script:allAvailablePackages[$curPkg].pkgSources = DeSerialize-PSObject -Path $curPkgPersistFilePath
        }
        else
        {
            $script:allAvailablePackages[$curPkg].pkgSources = [ordered]@{}
                
            $curPkgDefaultModuleSource = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property ([ordered]@{
                Name = $curPkgDefaultSourceName
                SourceLocation = $script:allAvailablePackages[$curPkg].pkgUrl
                Trusted=$false
                Registered= $true
                InstallationPolicy = "Untrusted"
            })

            $script:allAvailablePackages[$curPkg].pkgSources.Add($curPkgDefaultSourceName, $curPkgDefaultModuleSource)
            Save-ModuleSources `
            -sourceToSave $script:allAvailablePackages[$curPkg].pkgSources `
            -filePathToSaveTo $curPkgPersistFilePath
        }
    }
}

function Get-DynamicOptions
{
    param
    (
        [Microsoft.PackageManagement.MetaProvider.PowerShell.OptionCategory]
        $category
    )

    switch($category)
    {
        Install 
        {
            Write-Output -InputObject (New-DynamicOption -Category $category -Name "Update" -ExpectedType Switch -IsRequired $false)
        }
    }
}

function Add-PackageSource
{
    [CmdletBinding()]
    param
    (
        [string]
        $Name,
         
        [string]
        $Location,

        [bool]
        $Trusted
    )

    Set-ModuleSourcesVariable

    $Options = $request.Options

    # Add new module source
    $moduleSource = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property ([ordered]@{
            Name = $Name
            SourceLocation = $Location            
            Trusted=$Trusted
            Registered= $true
            InstallationPolicy = if($Trusted) {'Trusted'} else {'Untrusted'}
    })

    #TODO: Check if name already exists
    $script:DockerSources.Add($Name, $moduleSource)

    #Save-ModuleSources

    Write-Output -InputObject (New-PackageSourceFromModuleSource -ModuleSource $moduleSource)
}

function Remove-PackageSource
{
    param
    (
        [string]
        $Name
    )
    
    Set-ModuleSourcesVariable -Force

    if(-not $script:DockerSources.Contains($Name))
    {
        Write-Error -Message "Package source $Name not found" `
                        -ErrorId "Package source $Name not found" `
                        -Category InvalidOperation `
                        -TargetObject $Name
        continue
    }

    $script:DockerSources.Remove($Name)

    #Save-ModuleSources
}

function Resolve-PackageSource
{
    Set-ModuleSourcesVariable
    $SourceName = $request.PackageSources
    if(-not $SourceName)
    {
        $SourceName = "*"
    }

    foreach($moduleSourceName in $SourceName)
    {
        if($request.IsCanceled)
        {
            return
        }

        $wildcardPattern = New-Object System.Management.Automation.WildcardPattern $moduleSourceName,$script:wildcardOptions
        $moduleSourceFound = $false

        $script:DockerSources.GetEnumerator() |  
            Microsoft.PowerShell.Core\Where-Object {$wildcardPattern.IsMatch($_.Key)} |  
                Microsoft.PowerShell.Core\ForEach-Object { 
                    $moduleSource = $script:DockerSources[$_.Key] 
                    $packageSource = New-PackageSourceFromModuleSource -ModuleSource $moduleSource 
                    Write-Output -InputObject $packageSource 
                    $moduleSourceFound = $true 
                }

        if(-not $moduleSourceFound)
        {
            $sourceName  = Get-SourceName -Location $moduleSourceName

            if($sourceName)
            {
                $moduleSource = $script:DockerSources[$sourceName]
                $packageSource = New-PackageSourceFromModuleSource -ModuleSource $moduleSource
                Write-Output -InputObject $packageSource
            }            
        }
    }
}

function New-PackageSourceFromModuleSource
{
    param
    (
        [Parameter(Mandatory=$true)]
        $ModuleSource
    )

    $packageSourceDetails = @{}

    # create a new package source
    $src =  New-PackageSource -Name $ModuleSource.Name `
                              -Location $ModuleSource.SourceLocation `
                              -Trusted $ModuleSource.Trusted `
                              -Registered $ModuleSource.Registered `
                              -Details $packageSourceDetails

    # return the package source object.
    Write-Output -InputObject $src
}

function Get-SourceName
{
    [CmdletBinding()]
    [OutputType("string")]
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Location
    )

    Set-ModuleSourcesVariable

    foreach ($curPkg in $script:allAvailablePackages.Keys)
    {
        $curPkgSources = $script:allAvailablePackages[$curPkg].pkgSources

        foreach($psModuleSource in $curPkgSources.Values)
        {
            if(($psModuleSource.Name -eq $Location) -or
                   ($psModuleSource.SourceLocation -eq $Location))
            {
                return $psModuleSource.Name
            }
        }
    }
}

function DownloadPackageHelper
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FastPackageReference,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Location,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $request
    )

    [string[]] $splitterArray = @("$separator")
    [string[]] $resultArray = $fastPackageReference.Split($splitterArray, [System.StringSplitOptions]::None)

    if((-not $resultArray) -or ($resultArray.count -ne 8)){Write-Debug "Fast package reference doesn't have required parts."}

    $source = $resultArray[0]
    $name = $resultArray[1]
    $version = $resultArray[2]
    $description = $resultArray[3]
    $originPath = $resultArray[5]
    $size = $resultArray[6]
    $sha = $resultArray[7]
    $date = $resultArray[4]

    $options = $request.Options

    foreach( $o in $options.Keys )
    {
        Write-Debug ( "OPTION: {0} => {1}" -f ($o, $options[$o]) )
    }

    $Force = $false
    if($options.ContainsKey("Force"))
    {
        $Force = $options['Force']
    }

    if(-not (Test-Path $Location))
    {
        if($Force)
        {
            Write-Verbose "Creating: $Location as it doesn't exist."
            mkdir $Location
        }
        else
        {
            $errorMessage = ("Cannot find the path '{0}' because it does not exist" -f $Location)
            ThrowError  -ExceptionName "System.ArgumentException" `
                    -ExceptionMessage $errorMessage `
                    -ErrorId "PathNotFound" `
                    -CallerPSCmdlet $PSCmdlet `
                    -ExceptionObject $Location `
                    -ErrorCategory InvalidArgument
        }
    }

    $fullDestinationPath = GenerateFullPath -Location $Location `
                                    -Name $name `
                                    -Version $Version

    if(Test-Path $fullDestinationPath)
    {
        if($Force)
        {
            $existingFileItem = get-item $fullDestinationPath
            if($existingFileItem.isreadonly)
            {
                throw "Cannot remove read-only file $fullDestinationPath. Remove read-only and use -Force again."
            }
            else
            {
                Write-Verbose "$fullDestinationPath already exists. Deleting and downloading again."
                Remove-Item $fullDestinationPath -Force
                DownloadFile -downloadUrl $originPath -destination $fullDestinationPath
            }
        }
        else
        {
            Write-Verbose "$fullDestinationPath already exists. Skipping save. Use -Force to overwrite."
        }
    }
    else
    {
        DownloadFile -downloadUrl $originPath -destination $fullDestinationPath
    }

    $hashCheck = VerifyHashCheck -destination $fullDestinationPath -hash $sha

    if((-not $hashCheck))
    {
        $null = remove-item -Path $fullDestinationPath -Force
        Write-Error -Message "Cannot verify the file SHA256. Deleting the file."                
    }

    Write-Verbose "Hash verified!"

    $savedWindowsPackageItem = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property ([ordered]@{
                        SourceName = $source
                        Name = $name
                        Version = $version
                        Description = $description 
                        Date = $date
                        URL = $originPath
                        Size = $size
                        sha256 = $sha
    })

    Write-Output (New-SoftwareIdentityFromDockerInfo $savedWindowsPackageItem)
}

function GenerateFullPath
{
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $Location,

        [Parameter(Mandatory=$true)]
        [System.String]
        $Name,

        [Parameter(Mandatory=$true)]
        [System.String]
        $Version
    )

    $fileExtension = "." + $script:Installer_Extension
    $Name = $Name.TrimEnd($fileExtension)
    $fileName = $Name + "-" + $Version.ToString().replace('.','-') + $fileExtension
    $fullPath = Join-Path $Location $fileName
    return $fullPath
}

function DownloadFile
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $downloadURL, 
        
        [Parameter(Mandatory=$true)]
        [System.String]
        $destination
    )

    try
    {
        if(-not (CheckDiskSpace -Destination $destination -URL $downloadURL))
        {
            return
        }

        # Download the file
        if($downloadURL.StartsWith("https://"))
        {
            Write-Verbose "Downloading $downloadUrl to $destination"
            $startTime = Get-Date
            Write-Verbose "About to download"
            Invoke-WebRequest -Uri $downloadURL `
                            -OutFile $destination

            Write-Verbose "Finished downloading"
            $endTime = Get-Date
            $difference = New-TimeSpan -Start $startTime -End $endTime
            $downloadTime = "Downloaded in " + $difference.Hours + " hours, " + $difference.Minutes + " minutes, " + $difference.Seconds + " seconds."
            Write-Verbose $downloadTime
        }
    }
    catch
    {
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName $_.Exception.GetType().FullName `
                    -ExceptionMessage $_.Exception.Message `
                    -ExceptionObject $downloadURL `
                    -ErrorId FailedToDownload `
                    -ErrorCategory InvalidOperation        
    }
}

function ThrowError
{
    param
    (        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCmdlet]
        $CallerPSCmdlet,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]        
        $ExceptionName,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ExceptionMessage,
        
        [System.Object]
        $ExceptionObject,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ErrorId,

        [parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Management.Automation.ErrorCategory]
        $ErrorCategory
    )
        
    $exception = New-Object $ExceptionName $ExceptionMessage;
    $errorRecord = New-Object System.Management.Automation.ErrorRecord $exception, $ErrorId, $ErrorCategory, $ExceptionObject    
    $CallerPSCmdlet.ThrowTerminatingError($errorRecord)
}

function CheckDiskSpace
{
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]        
        $Destination, 
                      
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]        
        $URL
    )

    $size = 0

    if($URL.StartsWith("https://"))
    {
        $response = Get-HttpResponse -Uri $URL
        $size = $response.Result.Content.Headers.ContentLength        
    }

    $parent = Split-Path $Destination -Parent
    $Drive = (Get-Item $parent).PSDrive.Name
    $getDriveSpace = get-ciminstance win32_logicaldisk | Where-Object {$_.DeviceID -match $Drive} | % Freespace

    $contentLengthInMB = [math]::Round($size/1mb, 2)
    $driveSpaceInIMB = [math]::Round($getDriveSpace/1mb, 2)

    Write-Verbose "Download size: $($contentLengthInMB)MB"
    Write-Verbose "Free space on the drive: $($driveSpaceInIMB)MB"

    if($size -ge ($getDriveSpace * 0.95))
    {
        Write-Error "Not enough space to save the file"
        return $false
    }

    return $true
}

function VerifyHashCheck
{
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]        
        $Destination, 
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]        
        $hash
    )

    Write-Verbose "Verifying Hash of the downloaded file."

    $fileHash = Get-FileHash -Path $Destination `
                                -Algorithm SHA256
    
    if($fileHash.Psobject.properties.name -Contains "Hash")
    {
        $fileSha256 = $fileHash.Hash
    }
    else
    {
        Write-Verbose "Hash for the original file not available."
        return $false
    }

    return ($hash -ieq $fileSha256)
}

function Test-AdminPrivilege
{
    [CmdletBinding()]
    [OutputType([bool])]
    Param()

    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
    # Check to see if we are currently running "as Administrator"
    return ($myWindowsPrincipal.IsInRole($adminRole))
}

function IsNanoServer
{
    if ($script:isNanoServerInitialized)
    {
        return $script:isNanoServer
    }
    else
    {
        $operatingSystem = Get-CimInstance -ClassName win32_operatingsystem
        $systemSKU = $operatingSystem.OperatingSystemSKU
        $script:isNanoServer = ($systemSKU -eq 109) -or ($systemSKU -eq 144) -or ($systemSKU -eq 143)
        $script:isNanoServerInitialized = $true
        return $script:isNanoServer
    }
}

function Install-NuGetClientBinary
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCmdlet]
        $CallerPSCmdlet,

        [parameter()]
        [switch]
        $Force
    )

    if($script:NuGetProvider)
    {
        return
    }

    $InstallNuGetProviderShouldContinueQuery = "DockerMsftProvider requires NuGet provider. The NuGet provider must be available in '{0}' or '{1}'. You can also install the NuGet provider by running 'Install-PackageProvider -Name NuGet -Force'. Do you want DockerMsftProvider to install and import the NuGet provider now?"
    $InstallNuGetProviderShouldContinueCaption = "NuGet provider is required to continue"
    $CouldNotInstallNuGetProvider = "NuGet provider is required. Please ensure that NuGet provider is installed."
    $DownloadingNugetProvider = "Installing NuGet provider."

    $bootstrapNuGetProvider = (-not $script:NuGetProvider)

    if($bootstrapNuGetProvider)
    {
        # Bootstrap the NuGet provider only if it is not available.
        # By default PackageManagement loads the latest version of the NuGet provider.
        $nugetProvider = PackageManagement\Get-PackageProvider -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                            Microsoft.PowerShell.Core\Where-Object {$_.Name -eq $script:NuGetProviderName}
        if($nugetProvider)
        {
            $script:NuGetProvider = $nugetProvider
            $bootstrapNuGetProvider = $false

            return
        }
        else
        {
            $nugetProvider = PackageManagement\Get-PackageProvider -ListAvailable -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                            Microsoft.PowerShell.Core\Where-Object {$_.Name -eq $script:NuGetProviderName}

            if($nugetProvider)
            {
                $null = PackageManagement\Import-PackageProvider -Name $script:NuGetProviderName -Force                
                $nugetProvider = PackageManagement\Get-PackageProvider -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                                    Microsoft.PowerShell.Core\Where-Object {$_.Name -eq $script:NuGetProviderName}
                if($nugetProvider)
                {
                    $script:NuGetProvider = $nugetProvider
                    $bootstrapNuGetProvider = $false

                    return
                }
            }
        }
    }

    # We should prompt only once for bootstrapping the NuGet provider
    
    # Should continue message for bootstrapping only NuGet provider
    $shouldContinueQueryMessage = $InstallNuGetProviderShouldContinueQuery -f @($script:NuGetBinaryProgramDataPath,$script:NuGetBinaryLocalAppDataPath)
    $shouldContinueCaption = $InstallNuGetProviderShouldContinueCaption

    if($Force -or $request.ShouldContinue($shouldContinueQueryMessage, $shouldContinueCaption))
    {
        if($bootstrapNuGetProvider)
        {
            Write-Verbose -Message $DownloadingNugetProvider

            $scope = 'CurrentUser'
            if(Test-AdminPrivilege)
            {
                $scope = 'AllUsers'
            }

            # Bootstrap the NuGet provider
            $null = PackageManagement\Install-PackageProvider -Name $script:NuGetProviderName `
                                                              -Scope $scope `
                                                              -Force

            # Force import ensures that nuget provider with minimum version got loaded.
            $null = PackageManagement\Import-PackageProvider -Name $script:NuGetProviderName `
                                                             -Force

            $nugetProvider = PackageManagement\Get-PackageProvider -Name $script:NuGetProviderName

            if ($nugetProvider)
            {
                $script:NuGetProvider = $nugetProvider
            }
        }
    }

    $message = $null
    $errorId = $null
    $failedToBootstrapNuGetProvider = $false

    if($bootstrapNuGetProvider -and -not $script:NuGetProvider)
    {
        $failedToBootstrapNuGetProvider = $true

        $message = $CouldNotInstallNuGetProvider
        $errorId = 'CouldNotInstallNuGetProvider'
    }

    # Throw the error message if one of the above conditions are met
    if($message -and $errorId)
    {
        ThrowError -ExceptionName "System.InvalidOperationException" `
                    -ExceptionMessage $message `
                    -ErrorId $errorId `
                    -CallerPSCmdlet $CallerPSCmdlet `
                    -ErrorCategory InvalidOperation
    }
}


