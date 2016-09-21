#region variables

$script:Providername = "MicrosoftDockerProvider"
$script:DockerSources = $null
$script:location_modules = "$env:TEMP\Docker"
$script:file_modules = "$script:location_modules\sources.txt"
$script:DockerSearchIndex = "DockerSearchIndex.json"
$script:Installer_Name = "InstallDocker"
$script:Installer_Extension = "zip"
$script:dockerURL = "http://go.microsoft.com/fwlink/?LinkID=825636&clcid=0x409"
$separator = "|#|"
$script:isNanoServerInitialized = $false
$script:isNanoServer = $false
$script:pathVar = "C:\\Program Files\\docker"
$script:wildcardOptions = [System.Management.Automation.WildcardOptions]::CultureInvariant -bor `
                          [System.Management.Automation.WildcardOptions]::IgnoreCase

$script:PSGetProgramDataPath = Microsoft.PowerShell.Management\Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
$script:PSGetAppLocalPath = Microsoft.PowerShell.Management\Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet'
$script:NuGetProviderName = "NuGet"
$script:NuGetProviderVersion  = [Version]'2.8.5.201'
$script:SupportsPSModulesFeatureName="supports-powershell-modules"
$script:FastPackRefHastable = @{}
$script:NuGetBinaryProgramDataPath="$env:ProgramFiles\PackageManagement\ProviderAssemblies"
$script:NuGetBinaryLocalAppDataPath="$env:LOCALAPPDATA\PackageManagement\ProviderAssemblies"
$script:NuGetProvider = $null
$script:nanoserverPackageProvider = "NanoServerPackage"

$script:SemVerTypeName = 'Microsoft.PackageManagement.Provider.Utility.SemanticVersion'
if('Microsoft.PackageManagement.NuGetProvider.SemanticVersion' -as [Type])
{
    $script:SemVerTypeName = 'Microsoft.PackageManagement.NuGetProvider.SemanticVersion'
}

Microsoft.PowerShell.Core\Set-StrictMode -Version Latest

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
    $null = Install-NuGetClientBinaries -CallerPSCmdlet $PSCmdlet

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

    $allResults = @()
    $allSources = Get-Sources -Sources $sources

    if(-not $MinimumVersion){$MinimumVersion = $null}
    if(-not $MaximumVersion){$MaximumVersion = $null}
    if(-not $RequiredVersion){$RequiredVersion = $null}

    foreach($currSource in $allSources)
    {
        $Location = $currSource.SourceLocation
        $sourceName = $currSource.Name

        if($location.StartsWith("http://") -or $location.StartsWith("https://"))
        {
            $allResults += Find-FromUrl -Source $Location `
                                            -SourceName $sourceName `
                                            -Name $names `
                                            -MinimumVersion $MinimumVersion `
                                            -MaximumVersion $MaximumVersion `
                                            -RequiredVersion $RequiredVersion `
                                            -AllVersions:$AllVersions
        }
        else
        {
            Write-Error "Bad source '$sourceName' with location at $location"
        }
    }

    #if( ($null -eq $allResults) -or (0 -eq $allResults.Count) )
    if(($null -eq $allResults) -or ($null -eq $allResults[0]))
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
    [CmdletBinding(SupportsShouldProcess = $true)]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $fastPackageReference
    )

    # Check if another installation exists
    if(Test-Path $env:ProgramFiles\docker\dockerd.exe)
    {
        Write-Error "An instance already exists. Skipping the installation."
        return
    }

    if(-not (Test-AdminPriviledges))
    {
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName "Admin mode Error" `
                    -ExceptionMessage "Installing docker needs administrator mode." `
                    -ErrorId FailedToDownload `
                    -ErrorCategory InvalidOperation
    }

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

    $splitterArray = @("$separator")
    $resultArray = $fastPackageReference.Split($splitterArray, [System.StringSplitOptions]::None)

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

        if(Test-Path $env:ProgramFiles\docker\dockerd.exe)
        {
            Write-Verbose "Trying to start the service..."
            $service = @()
            $service += get-service | where {$_.Name -eq 'Docker'}
            if($service.count -eq 0)
            {
                $null = New-Service -Name Docker -BinaryPathName "$env:ProgramFiles\docker\dockerd.exe --run-service"
            }
        }
        else
        {
            Write-Error "Unable to expand docker to Program Files."
        }
    }
    catch
    {
        $null = remove-item $destination -Force
        $ErrorMessage = $_.Exception.Message
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName $_.Exception.GetType().FullName `
                    -ExceptionMessage $ErrorMessage `
                    -ErrorId FailedToDownload `
                    -ErrorCategory InvalidOperation
    }

    $options = $request.Options
    $noRestart = $false

    if($options)
    {
        foreach( $o in $options.Keys )
        {
            Write-Debug ("OPTION: {0} => {1}" -f ($o, $request.Options[$o]) )
        }

        if($options.ContainsKey('NoRestart'))
        {
            $noRestart = $true
        }            
    }

    # Update the path variable
    $null = Update-PathVar

    # Clean up
    Write-Verbose "Removing the archive: $destination"
    $null = remove-item $destination -Force

    Write-Output $downloadOutput

    if(-not $noRestart)
    {
        if($request.ShouldContinue("Should I restart the computer", "Restarting the computer"))
        {
            Restart-Computer -ComputerName $env:COMPUTERNAME
        }
    }
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

    if(-not (Test-AdminPriviledges))
    {
        ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName $_.Exception.GetType().FullName `
                    -ExceptionMessage "Installing docker needs administrator mode." `
                    -ErrorId FailedToDownload `
                    -ErrorCategory InvalidOperation
    }

    # Stop docker service
    $dockerService = Get-Service | Where-Object {$_.Name -eq "docker"}
    if($null -eq $dockerService)
    {
        # Docker service is not available
        Write-Error "Docker Service is not available."
    }

    if(($dockerService.Status -eq "Started") -or ($dockerService.Status -eq "Running"))
    {
        $null = stop-service docker
    }

    if(Test-Path $env:ProgramFiles\docker\dockerd.exe)
    {
        Write-Verbose "Unregistering the service"
        $null = & "$env:ProgramFiles\docker\dockerd.exe" --unregister-service
        
        Write-Verbose "Removing the docker files"
        $null = Get-ChildItem -Path $env:ProgramFiles\docker -Recurse | Remove-Item -force -Recurse
    }
    else 
    {
        Write-Error "Docker is not present under the Program Files. Please check the installation."
    }

    Write-Verbose "Removing the path variable"
    $null = Remove-PathVar

    Write-Verbose "Uninstalling container feature from windows"
    UninstallContainer
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

    if(Test-Path $env:ProgramFiles\docker\dockerd.exe)
    {
        $dockerVersion = & "$env:ProgramFiles\docker\dockerd.exe" --version
        $resultArr = $dockerVersion -split ","
        $version = ($resultArr[0].Trim() -split " ")[2]
        #$build = ($resultArr[1].Trim() -split " ")[1]
        $name = "docker"

        $dockerSWID = @{
            Name = $name
            version = $version
            Source = "DockerDefault"
            #build = $build
            versionScheme = "MultiPartNumeric"
            fastPackageReference = $name
        }   

        New-SoftwareIdentity @dockerSWID
    }
    else
    {
        $null        
    }
}

#endregion One-Get Required Functions

#region Helper-Functions

function InstallContainer
{
    if(IsNanoServer)
    {        
        HandleProvider

        # Find Container Package
        $containerPackage = Find-NanoServerPackage -Name *Container* -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

        if($null -eq $containerPackage)
        {
            ThrowError -CallerPSCmdlet $PSCmdlet `
                        -ExceptionName "Install Containers" `
                        -ExceptionMessage "Unable to find the Containers Package from NanoServerPackage Module." `
                        -ErrorId FailedToDownload `
                        -ErrorCategory InvalidOperation
        }

        $install = $containerPackage | Install-NanoServerPackage -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    }
    else
    {
        $null = Install-WindowsFeature containers
    }
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
    # Check if the nanoServerpackage provider is present
    # if not download and install
    if($null -eq (Get-PackageProvider -Name $script:nanoserverPackageProvider -ErrorAction SilentlyContinue -WarningAction SilentlyContinue))
    {
        $repositories = Get-PSRepository
        if($null -eq $repositories){$null = Register-PSRepository -Default}

        $nanoserverPackage = Find-Module -Name $script:nanoserverPackageProvider -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if($null -eq $nanoserverPackage)
        {
            ThrowError -CallerPSCmdlet $PSCmdlet `
                    -ExceptionName "Install Containers" `
                    -ExceptionMessage "Unable to find the NanoserverPackage to install Containers on the Nano Server." `
                    -ErrorId FailedToDownload `
                    -ErrorCategory InvalidOperation
        }

        # Install the provider 
        $null = $nanoserverPackage | Install-Module -Force
    }
    
    # Import the provider
    $null = Import-PackageProvider -Name $script:nanoserverPackageProvider -Force
    $null = Import-module -Name $script:nanoserverPackageProvider -Force
}

function Update-PathVar
{
    $pathVariable = "C:\Program Files\docker"

    if(IsNanoServer)
    {
        $currPath = [Environment]::GetEnvironmentVariable("Path")
        if($currPath -match $script:pathVar) {return}
        $null = [Environment]::SetEnvironmentVariable("Path", $env:Path + ";" + $pathVariable)
    }
    else
    {
        $currPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
        if($currPath -match $script:pathVar) {return}
        $null = [Environment]::SetEnvironmentVariable("Path", $env:Path + ";" + $pathVariable, [EnvironmentVariableTarget]::Machine)
    }
}

function Remove-PathVar
{
    if(IsNanoServer)
    {
        $currPath = [Environment]::GetEnvironmentVariable("Path")
        if($currPath -notmatch $script:pathVar) {return}

        $newPath = $currPath -replace ($script:pathVar),$null
        $newPath = $newPath -replace (";;"),";"
        $null = [Environment]::SetEnvironmentVariable("Path", $newPath)
    }
    else
    {
        $currPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
        if($currPath -notmatch $script:pathVar) {return}

        $newPath = $currPath -replace ($script:pathVar),$null
        $newPath = $newPath -replace (";;"),";"
        $null = [Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)        
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
    if(-not (Test-Path $script:location_modules))
    {
        $null = mkdir $script:location_modules
    }

    # seralize module
    Microsoft.PowerShell.Utility\Out-File -FilePath $script:file_modules `
                                            -Force `
                                            -InputObject ([System.Management.Automation.PSSerializer]::Serialize($script:DockerSources))
}

function Get-Sources
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

    $searchFile = Get-SearchIndex -fwdLink $Location `
                                    -SourceName $SourceName

    [String] $searchFileContent = Get-Content -Path $searchFile

    if($null -eq $searchFileContent)
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
        if($versions.$RequiredVersion)
        {
            $obj = Get-ResultObject -JSON $versions -Version $RequiredVersion
            $searchResults += $obj
            return $searchResults
        }
        else {
            return $null
        }
    }

    $searchDictionary = @{}
    $savedVersion = $script:SemVerTypeName::new('0.0.0')
    
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

            $thisVersion = $script:SemVerTypeName::new($versionValue)

            if($MinimumVersion)
            {
                if($thisVersion -ge $MinimumVersion)
                {
                    if($thisVersion -ge $savedVersion) {$savedVersion = $thisVersion}
                    $toggle = $true
                }
                else 
                {
                    $toggle = $false
                }
            }

            if($MaximumVersion)
            {
                if($thisVersion -le $MaximumVersion)
                {
                    if($thisVersion -ge $savedVersion) {$savedVersion = $thisVersion}
                    $toggle = $true
                }
                else 
                {
                    $toggle = $false
                }              
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
        if([bool]$versions.$version.Psobject.properties.name -match "notes")
        {
            $URL = $versions.$Version.'notes'
            $description = (Invoke-WebRequest -Uri $URL).Content
        }
        else
        {
            $description = "Docker version: " + $Version
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

    if($null -eq $response)
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

function Save-ModuleSources
{
    # check if exists
    if(-not (Test-Path $script:location_modules))
    {
        $null = mkdir $script:location_modules -Force
    }

    # seralize module
    Microsoft.PowerShell.Utility\Out-File -FilePath $script:file_modules `
                                            -Force `
                                            -InputObject ([System.Management.Automation.PSSerializer]::Serialize($script:DockerSources))
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
            Write-Output -InputObject (New-DynamicOption -Category $category -Name "NoRestart" -ExpectedType Switch -IsRequired $false)
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

    if((-not $hashCheck) -and (-not $Force))
    {
        $null = remove-item -Path $fullDestinationPath -Force
        Write-Error -Message "Cannot verify the file SHA256. Deleting the file."                
    }

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
        if($downloadURL.StartsWith("http://") -or $downloadURL.StartsWith("https://"))
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
        elseif($downloadURL.StartsWith("\\"))
        {
            $startTime = Get-Date
            $null = copy-item -Path $downloadURL -Destination $destination -Force
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

    if($URL.StartsWith("http://") -or $URL.StartsWith("https://"))
    {
        $response = Get-HttpResponse -Uri $URL
        $size = $response.Result.Content.Headers.ContentLength        
    }
    elseif($URL.StartsWith("\\"))
    {
        $size = (get-item $URL).Length
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

    $fileHash = Get-FileHash -Path $Destination `
                                -Algorithm SHA256
    
    if($fileHash.Psobject.properties.name -Contains "Hash")
    {
        $fileSha256 = $fileHash.Hash
    }
    else
    {
        return $false
    }

    return ($hash -ieq $fileSha256)
}

function Test-AdminPriviledges
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

function Install-NuGetClientBinaries
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    #[CmdletBinding()]
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

    $InstallNuGetProviderShouldContinueQuery = "PowerShellGet requires NuGet provider version '{0}' or newer to interact with NuGet-based repositories. The NuGet provider must be available in '{1}' or '{2}'. You can also install the NuGet provider by running 'Install-PackageProvider -Name NuGet -MinimumVersion {0} -Force'. Do you want PowerShellGet to install and import the NuGet provider now?"
    $InstallNuGetBinariesShouldContinueQuery2 = "PowerShellGet requires NuGet.exe and NuGet provider version '{0}' or newer to interact with the NuGet-based repositories. Do you want PowerShellGet to install both NuGet.exe and NuGet provider now?"
    $InstallNuGetBinariesShouldContinueCaption2 = "NuGet.exe and NuGet provider are required to continue"
    $InstallNuGetProviderShouldContinueCaption = "NuGet provider is required to continue"
    $CouldNotInstallNuGetProvider = "NuGet provider is required to interact with NuGet-based repositories. Please ensure that '{0}' or newer version of NuGet provider is installed."
    $CouldNotInstallNuGetExe = "NuGet.exe is required to interact with NuGet-based repositories. Please ensure that NuGet.exe is available under one of the paths specified in PATH environment variable value."
    $CouldNotInstallNuGetBinaries2 = "PowerShellGet requires NuGet.exe and NuGet provider version '{0}' or newer to interact with the NuGet-based repositories. Please ensure that '{0}' or newer version of NuGet provider is installed and NuGet.exe is available under one of the paths specified in PATH environment variable value."    
    $DownloadingNugetProvider = "Installing NuGet provider."

    $bootstrapNuGetProvider = (-not $script:NuGetProvider)

    if($bootstrapNuGetProvider)
    {
        # Bootstrap the NuGet provider only if it is not available.
        # By default PackageManagement loads the latest version of the NuGet provider.
        $nugetProvider = PackageManagement\Get-PackageProvider -ErrorAction SilentlyContinue -WarningAction SilentlyContinue |
                            Microsoft.PowerShell.Core\Where-Object { 
                                                                     $_.Name -eq $script:NuGetProviderName -and 
                                                                     $_.Version -ge $script:NuGetProviderVersion
                                                                   }
        if($nugetProvider)
        {
            $script:NuGetProvider = $nugetProvider
            $bootstrapNuGetProvider = $false
        }
    }

    # On Nano server we don't need NuGet.exe
    if(-not $bootstrapNuGetProvider -and (IsNanoServer))
    {
        return
    }

    # We should prompt only once for bootstrapping the NuGet provider and/or NuGet.exe
    
    # Should continue message for bootstrapping only NuGet provider
    $shouldContinueQueryMessage = $InstallNuGetProviderShouldContinueQuery -f @($script:NuGetProviderVersion,$script:NuGetBinaryProgramDataPath,$script:NuGetBinaryLocalAppDataPath)
    $shouldContinueCaption = $InstallNuGetProviderShouldContinueCaption

    # Should continue message for bootstrapping both NuGet provider and NuGet.exe
    if($bootstrapNuGetProvider)
    {
        $shouldContinueQueryMessage = $InstallNuGetBinariesShouldContinueQuery2 -f @($script:NuGetProviderVersion,$script:NuGetBinaryProgramDataPath,$script:NuGetBinaryLocalAppDataPath)
        $shouldContinueCaption = $InstallNuGetBinariesShouldContinueCaption2
    }

    if($Force -or $request.ShouldContinue($shouldContinueQueryMessage, $shouldContinueCaption))
    {
        if($bootstrapNuGetProvider)
        {
            Write-Verbose -Message $DownloadingNugetProvider

            $scope = 'CurrentUser'
            if(Test-AdminPriviledges)
            {
                $scope = 'AllUsers'
            }

            # Bootstrap the NuGet provider
            $null = PackageManagement\Install-PackageProvider -Name $script:NuGetProviderName `
                                                              -MinimumVersion $script:NuGetProviderVersion `
                                                              -Scope $scope `
                                                              -Force

            # Force import ensures that nuget provider with minimum version got loaded.
            $null = PackageManagement\Import-PackageProvider -Name $script:NuGetProviderName `
                                                             -MinimumVersion $script:NuGetProviderVersion `
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

        $message = $CouldNotInstallNuGetProvider -f @($script:NuGetProviderVersion)
        $errorId = 'CouldNotInstallNuGetProvider'
    }

    # Change the error id and message if both NuGet provider and NuGet.exe are not installed.
    if($failedToBootstrapNuGetProvider)
    {
        $message = $CouldNotInstallNuGetBinaries2 -f @($script:NuGetProviderVersion)
        $errorId = 'CouldNotInstallNuGetBinaries'
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