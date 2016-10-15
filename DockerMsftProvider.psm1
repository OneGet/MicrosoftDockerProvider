
#########################################################################################
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# DockerMsftProvider
#
#########################################################################################

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest

#region variables

$script:Providername = "DockerMsftProvider"
$script:DockerSources = $null
$script:location_modules = Microsoft.PowerShell.Management\Join-Path -Path $env:TEMP -ChildPath $script:ProviderName
$script:location_sources= Microsoft.PowerShell.Management\Join-Path -Path $env:LOCALAPPDATA -ChildPath $script:ProviderName
$script:file_modules = Microsoft.PowerShell.Management\Join-Path -Path $script:location_sources -ChildPath "sources.txt"
$script:DockerSearchIndex = "DockerSearchIndex.json"
$script:Installer_Extension = "zip"
$script:dockerURL = "https://go.microsoft.com/fwlink/?LinkID=825636&clcid=0x409"
$separator = "|#|"
$script:restartRequired = $false
$script:isNanoServerInitialized = $false
$script:isNanoServer = $false
$script:SystemEnvironmentKey = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
$script:pathVar = Microsoft.PowerShell.Management\Join-Path -Path $env:ProgramFiles -ChildPath "Docker"
$script:pathDockerD = Microsoft.PowerShell.Management\Join-Path -Path $env:ProgramFiles -ChildPath "Docker\dockerd.exe"
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
        $names = @('')
    }

    $allResults = @()
    $allSources = Get-SourceList -Sources $sources

    foreach($currSource in $allSources)
    {
        $Location = $currSource.SourceLocation
        $sourceName = $currSource.Name

        if($location.StartsWith("https://"))
        {
            $tempResults = @()
            $tempResults += Find-FromUrl -Source $Location `
                                            -SourceName $sourceName `
                                            -Name $names `
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
            Write-Verbose "Updating the docker installation."
            $update = $true
        }

        if($options.ContainsKey("Force"))
        {
            $force = $true
        }
    }

    if(Test-Path $script:pathDockerD)
    {
        if($update -or $force)
        {
            # Uninstall if another installation exists
            UninstallHelper
        }
        elseif(-not $force)
        {
            $dockerVersion = & "$env:ProgramFiles\Docker\dockerd.exe" --version
            $resultArr = $dockerVersion -split ","
            $version = ($resultArr[0].Trim() -split " ")[2]

            Write-Verbose "Docker $version already exists. Skipping install. Use -force to install anyway."
            return
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

            return
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

    # Install
    try 
    {
        Write-Verbose "Trying to unzip : $destination"
        $null = Expand-Archive -Path $destination -DestinationPath $env:ProgramFiles -Force

        # Rename the docker folder to become Docker
        $dummyName = 'dummyName'
        $null = Rename-Item -Path $env:ProgramFiles\docker -NewName $env:ProgramFiles\$dummyName
        $null = Rename-Item -Path $env:ProgramFiles\$dummyName -NewName $env:ProgramFiles\Docker        

        if(Test-Path $script:pathDockerD)
        {
            Write-Verbose "Trying to enable the docker service..."
            $service = get-service -Name Docker -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            if(-not $service)
            {
                $null = New-Service -Name Docker -BinaryPathName "$env:ProgramFiles\Docker\dockerd.exe --run-service"
            }
        }
        else
        {
            Write-Error "Unable to expand docker to Program Files."
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
    $null = SaveInfo -Source $source

    # Update the path variable
    $null = Update-PathVar

    if($script:restartRequired)
    {
        Write-Warning "A restart is required to start docker service. Please restart your machine."
        Write-Warning "After the restart please start the docker service."
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

    UninstallHelper

    Write-Verbose "Uninstalling container feature from windows"
    UninstallContainer

    [string[]] $splitterArray = @("$separator")
    [string[]] $resultArray = $fastPackageReference.Split($splitterArray, [System.StringSplitOptions]::None)

    if((-not $resultArray) -or ($resultArray.count -ne 3)){Write-Debug "Fast package reference doesn't have required parts."}

    $name = $resultArray[0]
    $version = $resultArray[1]
    $source = $resultArray[2]

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

    $name = 'docker'
    $version = ''
    $source = ''

    if(Test-Path $env:ProgramFiles\Docker\$script:MetadataFileName) 
    {
        $metaContent = (Get-Content -Path $env:ProgramFiles\Docker\$script:MetadataFileName)

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
            $metaContentParsed = (Get-Content -Path $env:ProgramFiles\Docker\$script:MetadataFileName) | ConvertFrom-Json
            if($metaContentParsed)
            {
                $source = if($metaContentParsed.PSObject.properties.name -contains 'SourceName') {$metaContentParsed.SourceName} else {'Unable To Retrieve Source from metadata.json'}
                $version = if($metaContentParsed.PSObject.properties.name -contains 'Version') {$metaContentParsed.Version} else {'Unable To Retrieve Version from metadata.json'}
            }            
        }
    }
    elseif(Test-Path $script:pathDockerD)
    {
        $dockerVersion = & "$env:ProgramFiles\Docker\dockerd.exe" --version
        $resultArr = $dockerVersion -split ","
        $version = ($resultArr[0].Trim() -split " ")[2]
        $source = ' '
    }
    else
    {
        return $null
    }

    $fastPackageReference = $name +
                                    $separator + $version +
                                    $separator + $source

    $dockerSWID = @{
        Name = $name
        version = $version
        Source = $source
        versionScheme = "MultiPartNumeric"
        fastPackageReference = $fastPackageReference
    }

    return New-SoftwareIdentity @dockerSWID
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
        $Source
    )

    # Create a file
    $metaFileInfo = New-Item -ItemType File -Path $env:ProgramFiles\docker -Name $script:MetadataFileName -Force

    if(-not $metaFileInfo)
    {
        # TODO: Handle File not created scenario
    }

    if(Test-Path $script:pathDockerD)
    {
        $dockerVersion = & "$env:ProgramFiles\Docker\dockerd.exe" --version
        $resultArr = $dockerVersion -split ","
        $version = ($resultArr[0].Trim() -split " ")[2]

        $metaInfo = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property ([ordered]@{
            SourceName = $source
            Version = $version 
        })

        $metaInfo | ConvertTo-Json > $metaFileInfo
    }
}

function UninstallHelper
{
    if(-not (Test-AdminPrivilege))
    {
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName "InvalidOperationException" `
                    -ExceptionMessage "Administrator rights are required to install docker." `
                    -ErrorId "AdminPrivilegesAreRequiredForInstall" `
                    -ErrorCategory InvalidOperation
    }

    # Stop docker service
    $dockerService = get-service -Name Docker -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    if(-not $dockerService)
    {
        # Docker service is not available
        Write-Error "Docker Service is not available."
    }

    if(($dockerService.Status -eq "Started") -or ($dockerService.Status -eq "Running"))
    {
        Write-Verbose "Trying to stop docker service"
        $null = stop-service docker
    }

    if(Test-Path $script:pathDockerD)
    {
        Write-Verbose "Unregistering the docker service"
        $null = & "$env:ProgramFiles\Docker\dockerd.exe" --unregister-service
        
        Write-Verbose "Removing the docker files"
        $null = Get-ChildItem -Path $env:ProgramFiles\Docker -Recurse | Remove-Item -force -Recurse

        if(Test-Path $env:ProgramFiles\Docker) {$null = Remove-Item $env:ProgramFiles\Docker -Force}
    }
    else 
    {
        Write-Error "Docker is not present under the Program Files. Please check the installation."
    }

    Write-Verbose "Removing the path variable"
    $null = Remove-PathVar
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
        $containerExists = Get-WindowsFeature -Name Containers
        if($containerExists -and $containerExists.Installed)
        {
            Write-Verbose "Containers feature is already installed. Skipping the install."
            return
        }
        else
        {
            Write-Verbose "Installing Containers..."
            $null = Install-WindowsFeature containers
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
        $null = Uninstall-WindowsFeature containers        
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
    $NameOfPath = "Path"
    
    # Set the environment variable in the Local Process
    $envVars = [Environment]::GetEnvironmentVariable($NameOfPath)
    $envArr = @()
    $envArr = $envVars -split ';'
    $envFlag = $true
    foreach($envItem in $envArr) 
    {
        if($envItem.Trim() -match [regex]::Escape($script:pathVar)) 
        {
            $envFlag = $false
            break
        }
    }
    if($envFlag)
    {
        $null = [Environment]::SetEnvironmentVariable($NameOfPath, $envVars + ";" + $script:pathVar)
    }

    # Set the environment variable in the Machine
    $currPath = (Microsoft.PowerShell.Management\Get-ItemProperty -Path $script:SystemEnvironmentKey -Name $NameOfPath -ErrorAction SilentlyContinue).Path    
    $currArr = @()
    $currArr = $currPath -split ';'
    $currFlag = $true
    foreach($currItem in $currArr)
    {
        if($currItem.Trim() -match [regex]::Escape($script:pathVar)) 
        {
            $currFlag = $true
            break
        }
    }
    if($currFlag)
    {
        $null = Microsoft.PowerShell.Management\Set-ItemProperty $script:SystemEnvironmentKey -Name $NameOfPath -Value ($currPath + ";" + $script:pathVar)

        # Nanoserver needs a reboot to persist the registry change
        if(IsNanoServer)
        {
            $script:restartRequired = $true
        }        
    }
}

function Remove-PathVar
{
    $NameOfPath = "Path"

    # Set the environment variable in the Local Process
    $envVars = [Environment]::GetEnvironmentVariable($NameOfPath)
    $envArr = @()
    $envArr = $envVars -split ';'
    $envFlag = $false
    foreach($envItem in $envArr) 
    {
        if($envItem.Trim() -match [regex]::Escape($script:pathVar))
        {
            $envFlag = $true
            break
        }
    }
    if($envFlag)
    {
        $newPath = $envVars -replace [regex]::Escape($script:pathVar),$null
        $newPath = $newPath -replace (";;"), ";"
        $null = [Environment]::SetEnvironmentVariable($NameOfPath, $newPath)
    }

    # Set the environment variable in the Machine
    $currPath = (Microsoft.PowerShell.Management\Get-ItemProperty -Path $script:SystemEnvironmentKey -Name $NameOfPath -ErrorAction SilentlyContinue).Path
    $currArr = @()
    $currArr = $currPath -split ';'
    $currFlag = $false
    foreach($currItem in $currArr)
    {
        if($currItem.Trim() -match [regex]::Escape($script:pathVar))
        {
            $currFlag = $true
            break
        }
    }
    if($currFlag)
    {
        $newPath = $envVars -replace [regex]::Escape($script:pathVar),$null
        $newPath = $newPath -replace (";;"), ";"
        $null = Microsoft.PowerShell.Management\Set-ItemProperty $script:SystemEnvironmentKey -Name $NameOfPath -Value $newPath
    }
}

function Set-ModuleSourcesVariable
{
    if(Microsoft.PowerShell.Management\Test-Path $script:file_modules)
    {
        $script:DockerSources = DeSerialize-PSObject -Path $script:file_modules
    }
    else
    {
        $script:DockerSources = [ordered]@{}
        $defaultModuleSource = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property ([ordered]@{
            Name = "DockerDefault"
            SourceLocation = $script:dockerURL
            Trusted=$false
            Registered= $true
            InstallationPolicy = "Untrusted"
        })

        $script:DockerSources.Add("DockerDefault", $defaultModuleSource)
        Save-ModuleSources
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
    # check if exists
    if(-not (Test-Path $script:location_sources))
    {
        $null = mkdir $script:location_sources
    }

    # seralize module
    Microsoft.PowerShell.Utility\Out-File -FilePath $script:file_modules `
                                            -Force `
                                            -InputObject ([System.Management.Automation.PSSerializer]::Serialize($script:DockerSources))
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
    
    foreach($mySource in $script:DockerSources.Values)
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

    return $listOfSources
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
        [string[]]
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

    if ([string]::IsNullOrWhiteSpace($Name))
    {
        $Name = "*"
    }

    if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Name))
    {
        if('docker' -notlike $Name) {return $null}
    }
    elseif('docker' -ne $Name) {return $Null}

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
    $csName = $channels.cs.alias
    $csVersion = $channels.$csName.version
    $channelValues = $channels | Get-Member -MemberType NoteProperty
    $searchResults = @()

    # If name is null or whitespace, interpret as *
    if ([string]::IsNullOrWhiteSpace($Name))
    {
        $Name = "*"
    }

    # if no versions are mentioned, just provide the default version, i.e.: CS 
    if((-not ($MinimumVersion -or $MaximumVersion -or $RequiredVersion -or $AllVersions)))
    {
        $RequiredVersion = $csVersion
    }

    # if a particular version is requested, provide that version only
    if($RequiredVersion)
    {
        if($versions.PSObject.properties.name -contains $RequiredVersion)
        {
            $obj = Get-ResultObject -JSON $versions -Version $RequiredVersion
            $searchResults += $obj
            return $searchResults
        }
        else {
            return $null
        }
    }

    $savedVersion = New-Object $script:SemVerTypeName -ArgumentList '0.0.0'
    
    # version requirement
    # compare different versions
    foreach($channel in $channelValues)
    {
        if($channel.Name -eq "cs")
        {
            continue
        }
        else 
        {
            $dockerName = "Docker"
            $versionName = $channel.Name
            $versionValue = $channels.$versionName.version
            if($versionName -eq $csName){$versionName = "cs"}

            $toggle = $false

            # Check if the search string has * in it
            if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($Name))
            {
                if($dockerName -like $Name)
                {
                    $toggle = $true
                }
                else
                {
                    continue
                }
            }
            else
            {
                if($dockerName -eq $Name)
                {
                    $toggle = $true
                }
                else
                {
                    continue
                }
            }

            $thisVersion = New-Object $script:SemVerTypeName -ArgumentList $versionValue

            if($MinimumVersion)
            {
                $convertedMinimumVersion =  New-Object $script:SemVerTypeName -ArgumentList $MinimumVersion
                if($thisVersion -ge $convertedMinimumVersion)
                {
                    $toggle = $true
                }
                else 
                {
                    $toggle = $false
                    continue
                }
            }

            if($MaximumVersion)
            {
                $convertedMaximumVersion =  New-Object $script:SemVerTypeName -ArgumentList $MaximumVersion
                if($thisVersion -le $convertedMaximumVersion)
                {
                    $toggle = $true
                }
                else
                {
                    $toggle = $false
                    continue
                }
            }

            if($toggle)
            {
                if($thisVersion -ge $savedVersion) {$savedVersion = $thisVersion}
            }

            if($AllVersions)
            {
                if($toggle)
                {
                    $obj = Get-ResultObject -JSON $versions -Version $versionValue
                    $searchResults += $obj
                }
            }
        }
    }

    if(-not $AllVersions)
    {
        if($savedVersion -eq '0.0.0'){return $null}

        $ver = $savedVersion.ToString()
        $obj = Get-ResultObject -JSON $versions -Version $ver
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
        $null = $obj | Add-Member NoteProperty Name "Docker"
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

    if(Microsoft.PowerShell.Management\Test-Path $script:file_modules)
    {
        $script:DockerSources = DeSerialize-PSObject -Path $script:file_modules
    }
    else
    {
        $script:DockerSources = [ordered]@{}
                
        $defaultModuleSource = Microsoft.PowerShell.Utility\New-Object PSCustomObject -Property ([ordered]@{
            Name = "DockerDefault"
            SourceLocation = $script:dockerURL
            Trusted=$false
            Registered= $true
            InstallationPolicy = "Untrusted"
        })

        $script:DockerSources.Add("DockerDefault", $defaultModuleSource)
        Save-ModuleSources
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

    Save-ModuleSources

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

    Save-ModuleSources
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

    foreach($psModuleSource in $script:DockerSources.Values)
    {
        if(($psModuleSource.Name -eq $Location) -or
           ($psModuleSource.SourceLocation -eq $Location))
        {
            return $psModuleSource.Name
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
            $saveItemPath = $PSScriptRoot + "\SaveHTTPItemUsingBITS.psm1"
            Import-Module "$saveItemPath"
            $startTime = Get-Date
            Write-Verbose "About to download"
            Save-HTTPItemUsingBitsTransfer -Uri $downloadURL `
                            -Destination $destination

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

#endregion

# SIG # Begin signature block
# MIIdlgYJKoZIhvcNAQcCoIIdhzCCHYMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3TXwtxEFBYWIFq38JoXohMZ2
# 8lagghhkMIIEwzCCA6ugAwIBAgITMwAAAMlkTRbbGn2zFQAAAAAAyTANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODU0
# WhcNMTgwOTA3MTc1ODU0WjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OkIxQjctRjY3Ri1GRUMyMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAotVXnfm6iRvJ
# s2GZXZXB2Jr9GoHX3HNAOp8xF/cnCE3fyHLwo1VF+TBQvObTTbxxdsUiqJ2Ew8DL
# jW8dolC9WqrPuP9Wj0gJNAdhnAYjtZN5fYEoGIsHBtuR3k+UxD2W7VWfjPDTY2zH
# e44WzfDvL2aXL2fomH73B7cx7YjT/7Du7vSdAHbr7SEdIyGJ5seMa+Y9MBJI48wZ
# A9CSnTGTFvhMXCYJuoR6Xc34A0EdHiTzfxY2tEWSiw5Xr+Oottc4IIHksNttYMgw
# HCu+tKqUlDkq5EdELh067r2Mv+OVkUkDQnLd1Vh/bP+yz92NKw7THQDYN7/4MTD2
# faNVsutryQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFB7ZK3kpWqMOy6M4tybE49oI
# BMpsMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBACvoEvJ84B3DuFj+SDfpkM3OCxYon2F4wWTOQmpDmTwysrQ0
# grXhxNqMVL7QRKk34of1uvckfIhsjnckTjkaFJk/bQc8n5wwTzCKJ3T0rV/Vasoh
# MbGm4y3UYEh9nflmKbPpNhps20EeU9sdNIkxsrpQsPwk59wv13STtUjywuTvpM5s
# 1dQOIiUWrAMR14ZzOSBA7kgWI+UEj5iaGYOczxD+wH+07llzwlIC4TyRXtgKFuMF
# AONNNYUedbi6oOX7IPo0hb5RVPuVqAFxT98xIheJXNod9lf2JLhGD+H/pXnkZJRr
# VjJFcuJeEAnYAe7b97+BfhbPgv8V9FIAwqTxgxIwggYHMIID76ADAgECAgphFmg0
# AAAAAAAcMA0GCSqGSIb3DQEBBQUAMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0wNzA0MDMxMjUzMDlaFw0yMTA0MDMx
# MzAzMDlaMHcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
# VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xITAf
# BgNVBAMTGE1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAJ+hbLHf20iSKnxrLhnhveLjxZlRI1Ctzt0YTiQP7tGn
# 0UytdDAgEesH1VSVFUmUG0KSrphcMCbaAGvoe73siQcP9w4EmPCJzB/LMySHnfL0
# Zxws/HvniB3q506jocEjU8qN+kXPCdBer9CwQgSi+aZsk2fXKNxGU7CG0OUoRi4n
# rIZPVVIM5AMs+2qQkDBuh/NZMJ36ftaXs+ghl3740hPzCLdTbVK0RZCfSABKR2YR
# JylmqJfk0waBSqL5hKcRRxQJgp+E7VV4/gGaHVAIhQAQMEbtt94jRrvELVSfrx54
# QTF3zJvfO4OToWECtR0Nsfz3m7IBziJLVP/5BcPCIAsCAwEAAaOCAaswggGnMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFCM0+NlSRnAK7UD7dvuzK7DDNbMPMAsG
# A1UdDwQEAwIBhjAQBgkrBgEEAYI3FQEEAwIBADCBmAYDVR0jBIGQMIGNgBQOrIJg
# QFYnl+UlE/wq4QpTlVnkpKFjpGEwXzETMBEGCgmSJomT8ixkARkWA2NvbTEZMBcG
# CgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UEAxMkTWljcm9zb2Z0IFJvb3Qg
# Q2VydGlmaWNhdGUgQXV0aG9yaXR5ghB5rRahSqClrUxzWPQHEy5lMFAGA1UdHwRJ
# MEcwRaBDoEGGP2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL21pY3Jvc29mdHJvb3RjZXJ0LmNybDBUBggrBgEFBQcBAQRIMEYwRAYIKwYB
# BQUHMAKGOGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljcm9z
# b2Z0Um9vdENlcnQuY3J0MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# BQUAA4ICAQAQl4rDXANENt3ptK132855UU0BsS50cVttDBOrzr57j7gu1BKijG1i
# uFcCy04gE1CZ3XpA4le7r1iaHOEdAYasu3jyi9DsOwHu4r6PCgXIjUji8FMV3U+r
# kuTnjWrVgMHmlPIGL4UD6ZEqJCJw+/b85HiZLg33B+JwvBhOnY5rCnKVuKE5nGct
# xVEO6mJcPxaYiyA/4gcaMvnMMUp2MT0rcgvI6nA9/4UKE9/CCmGO8Ne4F+tOi3/F
# NSteo7/rvH0LQnvUU3Ih7jDKu3hlXFsBFwoUDtLaFJj1PLlmWLMtL+f5hYbMUVbo
# nXCUbKw5TNT2eb+qGHpiKe+imyk0BncaYsk9Hm0fgvALxyy7z0Oz5fnsfbXjpKh0
# NbhOxXEjEiZ2CzxSjHFaRkMUvLOzsE1nyJ9C/4B5IYCeFTBm6EISXhrIniIh0EPp
# K+m79EjMLNTYMoBMJipIJF9a6lbvpt6Znco6b72BJ3QGEe52Ib+bgsEnVLaxaj2J
# oXZhtG6hE6a/qkfwEm/9ijJssv7fUciMI8lmvZ0dhxJkAj0tr1mPuOQh5bWwymO0
# eFQF1EEuUKyUsKV4q7OglnUa2ZKHE3UiLzKoCG6gW4wlv6DvhMoh1useT8ma7kng
# 9wFlb4kLfchpyOZu6qeXzjEp/w7FW1zYTRuh2Povnj8uVRZryROj/TCCBhAwggP4
# oAMCAQICEzMAAABkR4SUhttBGTgAAAAAAGQwDQYJKoZIhvcNAQELBQAwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTAeFw0xNTEwMjgyMDMxNDZaFw0xNzAx
# MjgyMDMxNDZaMIGDMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MQ0wCwYDVQQLEwRNT1BSMR4wHAYDVQQDExVNaWNyb3NvZnQgQ29ycG9yYXRpb24w
# ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCTLtrY5j6Y2RsPZF9NqFhN
# FDv3eoT8PBExOu+JwkotQaVIXd0Snu+rZig01X0qVXtMTYrywPGy01IVi7azCLiL
# UAvdf/tqCaDcZwTE8d+8dRggQL54LJlW3e71Lt0+QvlaHzCuARSKsIK1UaDibWX+
# 9xgKjTBtTTqnxfM2Le5fLKCSALEcTOLL9/8kJX/Xj8Ddl27Oshe2xxxEpyTKfoHm
# 5jG5FtldPtFo7r7NSNCGLK7cDiHBwIrD7huTWRP2xjuAchiIU/urvzA+oHe9Uoi/
# etjosJOtoRuM1H6mEFAQvuHIHGT6hy77xEdmFsCEezavX7qFRGwCDy3gsA4boj4l
# AgMBAAGjggF/MIIBezAfBgNVHSUEGDAWBggrBgEFBQcDAwYKKwYBBAGCN0wIATAd
# BgNVHQ4EFgQUWFZxBPC9uzP1g2jM54BG91ev0iIwUQYDVR0RBEowSKRGMEQxDTAL
# BgNVBAsTBE1PUFIxMzAxBgNVBAUTKjMxNjQyKzQ5ZThjM2YzLTIzNTktNDdmNi1h
# M2JlLTZjOGM0NzUxYzRiNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUC
# lTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# b3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUF
# BwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1Ud
# EwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAIjiDGRDHd1crow7hSS1nUDWvWas
# W1c12fToOsBFmRBN27SQ5Mt2UYEJ8LOTTfT1EuS9SCcUqm8t12uD1ManefzTJRtG
# ynYCiDKuUFT6A/mCAcWLs2MYSmPlsf4UOwzD0/KAuDwl6WCy8FW53DVKBS3rbmdj
# vDW+vCT5wN3nxO8DIlAUBbXMn7TJKAH2W7a/CDQ0p607Ivt3F7cqhEtrO1Rypehh
# bkKQj4y/ebwc56qWHJ8VNjE8HlhfJAk8pAliHzML1v3QlctPutozuZD3jKAO4WaV
# qJn5BJRHddW6l0SeCuZmBQHmNfXcz4+XZW/s88VTfGWjdSGPXC26k0LzV6mjEaEn
# S1G4t0RqMP90JnTEieJ6xFcIpILgcIvcEydLBVe0iiP9AXKYVjAPn6wBm69FKCQr
# IPWsMDsw9wQjaL8GHk4wCj0CmnixHQanTj2hKRc2G9GL9q7tAbo0kFNIFs0EYkbx
# Cn7lBOEqhBSTyaPS6CvjJZGwD0lNuapXDu72y4Hk4pgExQ3iEv/Ij5oVWwT8okie
# +fFLNcnVgeRrjkANgwoAyX58t0iqbefHqsg3RGSgMBu9MABcZ6FQKwih3Tj0DVPc
# gnJQle3c6xN3dZpuEgFcgJh/EyDXSdppZzJR4+Bbf5XA/Rcsq7g7X7xl4bJoNKLf
# cafOabJhpxfcFOowMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEw
# HhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
# aWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# q/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2Avw
# OMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eW
# WcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1
# eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le
# 2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+
# 0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2
# zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv
# 1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLn
# JN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31n
# gOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+Hgg
# WCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAG
# CSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZ
# BgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/
# BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8E
# UzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEB
# BFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcw
# gZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNy
# b3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwIC
# MDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBu
# AHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOS
# mUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQ
# VdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQ
# dION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive
# /DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrC
# xq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/
# E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ
# 7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANah
# Rr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3
# S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1W
# Tk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1t
# bWrJUnMTDXpQzTGCBJwwggSYAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcg
# UENBIDIwMTECEzMAAABkR4SUhttBGTgAAAAAAGQwCQYFKw4DAhoFAKCBsDAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAjBgkqhkiG9w0BCQQxFgQU/W2v603fbR78A4ZAP0H3xRJzqKowUAYKKwYB
# BAGCNwIBDDFCMECgFoAUAFAAbwB3AGUAcgBTAGgAZQBsAGyhJoAkaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL1Bvd2VyU2hlbGwgMA0GCSqGSIb3DQEBAQUABIIBAHRy
# lC+lxVsmWx3oUSALIkNP7tsWYaJ69MPTvVVRtHrZyHklhGbMVjGZVeNlUMIf8jVh
# 3SUj3YoLcl57MdlpeJux/8tmOG+sO4/FVas/ukDRHgunirLS46q28klsmsCN7cdp
# CT8t5+bc1uJW9fz3jpASYXdT5vLoe3OujirmWz06BIuq1Ya3YVNaShbMM7gz4uMM
# VeijVA2RTUVQbYyf5StCnhggler6Wj84W6AumTp91AYBWKNAAtj1yZEB3UuAFT7w
# USpcPzezN3lsg/s2wdTYZnAmvpQS2jau4XXvmxDEQybd6um1gHI/TtY8HYBI7HU3
# WU6L7oxoyHjzKBpODyChggIoMIICJAYJKoZIhvcNAQkGMYICFTCCAhECAQEwgY4w
# dzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMY
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBAhMzAAAAyWRNFtsafbMVAAAAAADJMAkG
# BSsOAwIaBQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJ
# BTEPFw0xNjEwMTMyMjMwMDNaMCMGCSqGSIb3DQEJBDEWBBSiwW+zC0Fq37MLxDey
# r3CVcJo0+zANBgkqhkiG9w0BAQUFAASCAQB3ogFQjbI5+pEWozVCyHMokS2hnh3R
# VXbjmbhoDvaZpdLQDM1E1DtwjREMHvASxtz0cNFsanAkrfuTbchgVGNRhhi4Jazw
# SnmiDH3josZkBLehSNgf+MRFJ5OT3yHX7AWiZVV5DmfInd3O3XIptAK4oTiNfn4w
# v1Qlmxp9fy/8479VdqPQAg/5DW5LVJNAFJkFMZFCJJHvzRZ7n7INmSSAc6vQhIRu
# uuLZR7biGITQFqT+0jlY9/X5eunifvJTjBlAN5AxPLmsxqnek3Yjick8NjaiTshV
# LAP5Rng22n98caodnO4OuFbNtMnN6oxsnOOsXySBGs680wRQtyZKKsgx
# SIG # End signature block
