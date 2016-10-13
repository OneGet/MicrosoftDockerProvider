
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

    if(-not $script:isNanoServer)
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
                        -ExceptionMessage "$script:hotFixID or later is required to install docker" `
                        -ErrorId "RequiredWindowsUpdateNotInstalled" `
                        -ErrorCategory InvalidOperation
            return
        }
    }
    else
    {
        Write-Warning "$script:hotFixID or later is required to install docker. Please ensure this is installed."
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
        if($script:isNanoServer)
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
# MIIasAYJKoZIhvcNAQcCoIIaoTCCGp0CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTwJvwv08w9FqVw3bV5CLIUyW
# HAKgghWDMIIEwzCCA6ugAwIBAgITMwAAALbYAJUMg2JtoQAAAAAAtjANBgkqhkiG
# 9w0BAQUFADB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwHhcNMTYwOTA3MTc1ODQ0
# WhcNMTgwOTA3MTc1ODQ0WjCBszELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBEU0UgRVNO
# OjMxQzUtMzBCQS03QzkxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlitSnGveWTDN
# e1jrQZjYpA9N4OXmCTtz/jy98iVz0ro/f2ELzjwkrzQycPykmlVlOxzzzaSIBmqK
# HiWJXU9m6mU0WS8/O8GV2U8d9PA057wJ/6+3ptVocqSANSNpXip5qKRl5P1Wac0Z
# 5oJ1NOXPnu1J4slB7ssE2ifDwS+0kHkTU3FdKeh8dAoC7GoQU0aFQdPFikvh7YRa
# gwPzzPVs96zCJdIY4gPGqdi8ajX3xrJI4th7QdO98fpj8f1CBJtlELMDiaMwUu0e
# 2VLTFE1sl1cyer4afcTuf+ENNRyiH+LJ5nHRK3/zkTYpjv8G/tfp3swk2ha9tsPP
# ddCge17XYQIDAQABo4IBCTCCAQUwHQYDVR0OBBYEFOjzQTSj/oQgLDnBEUwqsxz4
# 7wKyMB8GA1UdIwQYMBaAFCM0+NlSRnAK7UD7dvuzK7DDNbMPMFQGA1UdHwRNMEsw
# SaBHoEWGQ2h0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY3Jvc29mdFRpbWVTdGFtcFBDQS5jcmwwWAYIKwYBBQUHAQEETDBKMEgGCCsG
# AQUFBzAChjxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFRpbWVTdGFtcFBDQS5jcnQwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQEFBQADggEBAGotNN2Ff2yTVo4VKnHCmG+PxMuqhs1ke1JE5bQu3bGRgIWX
# riEZvWVqgDUihF4GmcPRHatBE9qtM5ewhDuSIGBf/5rqskW00Q4Kgb7mDtx/sOV7
# wNXJ0HjFgyNRqVDVxVE6uZ8bCTi+TjhfuIBZj85UbdfG/qtPkQkzgmaK83dgLPEH
# T8Je8gd7orVPNkI3lqkQbQ8X4ZISiP+heRsPYtlgeMGvnle5ssGzB2O5Ozt527Fa
# Ztpxi32uN1Qk8hV7xM+Z4ujOGqJFxVQfCGlMU0tXTvaRNoNpKWSp2fjYHyasLXAU
# y7ZhZHq7qWAilzmqCFYZIDPJmjUtm1/hqhqqqxQwggTtMIID1aADAgECAhMzAAAB
# QJap7nBW/swHAAEAAAFAMA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBMB4XDTE2MDgxODIwMTcxN1oXDTE3MTEwMjIwMTcxN1owgYMxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIx
# HjAcBgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBANtLi+kDal/IG10KBTnk1Q6S0MThi+ikDQUZWMA81ynd
# ibdobkuffryavVSGOanxODUW5h2s+65r3Akw77ge32z4SppVl0jII4mzWSc0vZUx
# R5wPzkA1Mjf+6fNPpBqks3m8gJs/JJjE0W/Vf+dDjeTc8tLmrmbtBDohlKZX3APb
# LMYb/ys5qF2/Vf7dSd9UBZSrM9+kfTGmTb1WzxYxaD+Eaxxt8+7VMIruZRuetwgc
# KX6TvfJ9QnY4ItR7fPS4uXGew5T0goY1gqZ0vQIz+lSGhaMlvqqJXuI5XyZBmBre
# ueZGhXi7UTICR+zk+R+9BFF15hKbduuFlxQiCqET92ECAwEAAaOCAWEwggFdMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSc5ehtgleuNyTe6l6pxF+QHc7Z
# ezBSBgNVHREESzBJpEcwRTENMAsGA1UECxMETU9QUjE0MDIGA1UEBRMrMjI5ODAz
# K2Y3ODViMWMwLTVkOWYtNDMxNi04ZDZhLTc0YWU2NDJkZGUxYzAfBgNVHSMEGDAW
# gBTLEejK0rQWWAHJNy4zFha5TJoKHzBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNDb2RTaWdQQ0Ff
# MDgtMzEtMjAxMC5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY0NvZFNpZ1BDQV8wOC0z
# MS0yMDEwLmNydDANBgkqhkiG9w0BAQUFAAOCAQEAa+RW49cTHSBA+W3p3k7bXR7G
# bCaj9+UJgAz/V+G01Nn5XEjhBn/CpFS4lnr1jcmDEwxxv/j8uy7MFXPzAGtOJar0
# xApylFKfd00pkygIMRbZ3250q8ToThWxmQVEThpJSSysee6/hU+EbkfvvtjSi0lp
# DimD9aW9oxshraKlPpAgnPWfEj16WXVk79qjhYQyEgICamR3AaY5mLPuoihJbKwk
# Mig+qItmLPsC2IMvI5KR91dl/6TV6VEIlPbW/cDVwCBF/UNJT3nuZBl/YE7ixMpT
# Th/7WpENW80kg3xz6MlCdxJfMSbJsM5TimFU98KNcpnxxbYdfqqQhAQ6l3mtYDCC
# BbwwggOkoAMCAQICCmEzJhoAAAAAADEwDQYJKoZIhvcNAQEFBQAwXzETMBEGCgmS
# JomT8ixkARkWA2NvbTEZMBcGCgmSJomT8ixkARkWCW1pY3Jvc29mdDEtMCsGA1UE
# AxMkTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTEwMDgz
# MTIyMTkzMloXDTIwMDgzMTIyMjkzMloweTELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQ
# Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycllcGTBkvx2aYCAg
# Qpl2U2w+G9ZvzMvx6mv+lxYQ4N86dIMaty+gMuz/3sJCTiPVcgDbNVcKicquIEn0
# 8GisTUuNpb15S3GbRwfa/SXfnXWIz6pzRH/XgdvzvfI2pMlcRdyvrT3gKGiXGqel
# cnNW8ReU5P01lHKg1nZfHndFg4U4FtBzWwW6Z1KNpbJpL9oZC/6SdCnidi9U3RQw
# WfjSjWL9y8lfRjFQuScT5EAwz3IpECgixzdOPaAyPZDNoTgGhVxOVoIoKgUyt0vX
# T2Pn0i1i8UU956wIAPZGoZ7RW4wmU+h6qkryRs83PDietHdcpReejcsRj1Y8wawJ
# XwPTAgMBAAGjggFeMIIBWjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTLEejK
# 0rQWWAHJNy4zFha5TJoKHzALBgNVHQ8EBAMCAYYwEgYJKwYBBAGCNxUBBAUCAwEA
# ATAjBgkrBgEEAYI3FQIEFgQU/dExTtMmipXhmGA7qDFvpjy82C0wGQYJKwYBBAGC
# NxQCBAweCgBTAHUAYgBDAEEwHwYDVR0jBBgwFoAUDqyCYEBWJ5flJRP8KuEKU5VZ
# 5KQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC5taWNyb3NvZnQuY29tL3Br
# aS9jcmwvcHJvZHVjdHMvbWljcm9zb2Z0cm9vdGNlcnQuY3JsMFQGCCsGAQUFBwEB
# BEgwRjBEBggrBgEFBQcwAoY4aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNyb3NvZnRSb290Q2VydC5jcnQwDQYJKoZIhvcNAQEFBQADggIBAFk5
# Pn8mRq/rb0CxMrVq6w4vbqhJ9+tfde1MOy3XQ60L/svpLTGjI8x8UJiAIV2sPS9M
# uqKoVpzjcLu4tPh5tUly9z7qQX/K4QwXaculnCAt+gtQxFbNLeNK0rxw56gNogOl
# VuC4iktX8pVCnPHz7+7jhh80PLhWmvBTI4UqpIIck+KUBx3y4k74jKHK6BOlkU7I
# G9KPcpUqcW2bGvgc8FPWZ8wi/1wdzaKMvSeyeWNWRKJRzfnpo1hW3ZsCRUQvX/Ta
# rtSCMm78pJUT5Otp56miLL7IKxAOZY6Z2/Wi+hImCWU4lPF6H0q70eFW6NB4lhhc
# yTUWX92THUmOLb6tNEQc7hAVGgBd3TVbIc6YxwnuhQ6MT20OE049fClInHLR82zK
# wexwo1eSV32UjaAbSANa98+jZwp0pTbtLS8XyOZyNxL0b7E8Z4L5UrKNMxZlHg6K
# 3RDeZPRvzkbU0xfpecQEtNP7LN8fip6sCvsTJ0Ct5PnhqX9GuwdgR2VgQE6wQuxO
# 7bN2edgKNAltHIAxH+IOVN3lofvlRxCtZJj/UBYufL8FIXrilUEnacOTj5XJjdib
# Ia4NXJzwoq6GaIMMai27dmsAHZat8hZ79haDJLmIz2qoRzEvmtzjcT3XAH5iR9HO
# iMm4GPoOco3Boz2vAkBq/2mbluIQqBC0N1AI1sM9MIIGBzCCA++gAwIBAgIKYRZo
# NAAAAAAAHDANBgkqhkiG9w0BAQUFADBfMRMwEQYKCZImiZPyLGQBGRYDY29tMRkw
# FwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MS0wKwYDVQQDEyRNaWNyb3NvZnQgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwHhcNMDcwNDAzMTI1MzA5WhcNMjEwNDAz
# MTMwMzA5WjB3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSEw
# HwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQCfoWyx39tIkip8ay4Z4b3i48WZUSNQrc7dGE4kD+7R
# p9FMrXQwIBHrB9VUlRVJlBtCkq6YXDAm2gBr6Hu97IkHD/cOBJjwicwfyzMkh53y
# 9GccLPx754gd6udOo6HBI1PKjfpFzwnQXq/QsEIEovmmbJNn1yjcRlOwhtDlKEYu
# J6yGT1VSDOQDLPtqkJAwbofzWTCd+n7Wl7PoIZd++NIT8wi3U21StEWQn0gASkdm
# EScpZqiX5NMGgUqi+YSnEUcUCYKfhO1VeP4Bmh1QCIUAEDBG7bfeI0a7xC1Un68e
# eEExd8yb3zuDk6FhArUdDbH895uyAc4iS1T/+QXDwiALAgMBAAGjggGrMIIBpzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQjNPjZUkZwCu1A+3b7syuwwzWzDzAL
# BgNVHQ8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwgZgGA1UdIwSBkDCBjYAUDqyC
# YEBWJ5flJRP8KuEKU5VZ5KShY6RhMF8xEzARBgoJkiaJk/IsZAEZFgNjb20xGTAX
# BgoJkiaJk/IsZAEZFgltaWNyb3NvZnQxLTArBgNVBAMTJE1pY3Jvc29mdCBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eYIQea0WoUqgpa1Mc1j0BxMuZTBQBgNVHR8E
# STBHMEWgQ6BBhj9odHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9k
# dWN0cy9taWNyb3NvZnRyb290Y2VydC5jcmwwVAYIKwYBBQUHAQEESDBGMEQGCCsG
# AQUFBzAChjhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY3Jv
# c29mdFJvb3RDZXJ0LmNydDATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkqhkiG9w0B
# AQUFAAOCAgEAEJeKw1wDRDbd6bStd9vOeVFNAbEudHFbbQwTq86+e4+4LtQSooxt
# YrhXAstOIBNQmd16QOJXu69YmhzhHQGGrLt48ovQ7DsB7uK+jwoFyI1I4vBTFd1P
# q5Lk541q1YDB5pTyBi+FA+mRKiQicPv2/OR4mS4N9wficLwYTp2OawpylbihOZxn
# LcVRDupiXD8WmIsgP+IHGjL5zDFKdjE9K3ILyOpwPf+FChPfwgphjvDXuBfrTot/
# xTUrXqO/67x9C0J71FNyIe4wyrt4ZVxbARcKFA7S2hSY9Ty5ZlizLS/n+YWGzFFW
# 6J1wlGysOUzU9nm/qhh6YinvopspNAZ3GmLJPR5tH4LwC8csu89Ds+X57H2146So
# dDW4TsVxIxImdgs8UoxxWkZDFLyzs7BNZ8ifQv+AeSGAnhUwZuhCEl4ayJ4iIdBD
# 6Svpu/RIzCzU2DKATCYqSCRfWupW76bemZ3KOm+9gSd0BhHudiG/m4LBJ1S2sWo9
# iaF2YbRuoROmv6pH8BJv/YoybLL+31HIjCPJZr2dHYcSZAI9La9Zj7jkIeW1sMpj
# tHhUBdRBLlCslLCleKuzoJZ1GtmShxN1Ii8yqAhuoFuMJb+g74TKIdbrHk/Jmu5J
# 4PcBZW+JC33Iacjmbuqnl84xKf8OxVtc2E0bodj6L54/LlUWa8kTo/0xggSXMIIE
# kwIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSMw
# IQYDVQQDExpNaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQQITMwAAAUCWqe5wVv7M
# BwABAAABQDAJBgUrDgMCGgUAoIGwMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEWBBTE
# msD25Oq7ARxD5TRChFlJQAt6rzBQBgorBgEEAYI3AgEMMUIwQKAWgBQAUABvAHcA
# ZQByAFMAaABlAGwAbKEmgCRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vUG93ZXJT
# aGVsbCAwDQYJKoZIhvcNAQEBBQAEggEACU13Sg+zAis2N25qCOigiF55PWmXfg6p
# XeQr9XEvRSu1ebGu49belMw1dINEMKCQGaCzRhhshikiABwV5/7LYdXkvZ0+ijQ+
# 5YhX4PUqsBDyvHXwBn1jezm5AdHt1hvudipjZ/bOggsQQimwhcW+GL+IpX6MGNwt
# XYAov7O6h7C+3tVrSWDkmOY5LF+ihyo8+1p70GkctxIaEqxchDXYNyOM502iMOMZ
# jDiq6vhOAiS03a+kSumj0yLO7kpFXA8T0GmzpTmwvpUhZydqMbED9un4iKIYSIiK
# zvHheeZRT69/2yfLW8IQQ4U2pyHHjpT/CSrSX4EiQHBecadtXC3A9aGCAigwggIk
# BgkqhkiG9w0BCQYxggIVMIICEQIBATCBjjB3MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSEwHwYDVQQDExhNaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0ECEzMAAAC22ACVDINibaEAAAAAALYwCQYFKw4DAhoFAKBdMBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTE2MTAxMzIxMDA0MFowIwYJ
# KoZIhvcNAQkEMRYEFGzt21BFcw7ufs8odkZiSir3w12zMA0GCSqGSIb3DQEBBQUA
# BIIBAGRvwVMjPNqw/PHX3aoMu5t5GTSoGqt9dMi1QdpWAfiN8L1DhXmwUqF7TRnV
# D4+VAgWsqkEQL8QeN5zZ5MoQonkNEnEyS5xAswzn5xqAvcsvjG8q/GJbgWpVvrE9
# yoqrIhkOK4peeze6Qb0MOx5pXSnezbN6S7zmljqhI/6pwj118tlvbji723sCjwKs
# kEZL1ysWPETyCsjT+yFBiUs7Ov+LBTjWoVqZzQBpzFGY8Ngd5pZ7R4WZ9rFPhcqv
# bfoArvtPMnD2QwaOqVhsyExu0GSgI6QSlLhJ82KiMceTuOi7RcxsUkNxO6ZyaRaX
# PiVcn4uJ5Ly1IhyASLm8xeAsuS4=
# SIG # End signature block
