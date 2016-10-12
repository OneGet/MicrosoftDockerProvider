### Introduction
#### Install a Docker image from the online Package repository

The Docker installer for Windows is now available in an online package repository.  They can be found and installed using the Docker provider of PackageManagement (a.k.a. <a href="http://www.oneget.org">OneGet</a>) PowerShell module.  The provider needs to be installed before using it. The following PowerShell cmdlets can be used to install the provider.
* Import-Module -Name DockerEngineProvider -Force
* Import-Packageprovider -Name DockerEngineProvider -Force

Once the provider is installed and imported, you can search, download, or install Docker using OneGet PowerShell cmdlets:
* Find-Package
* Save-Package
* Install-Package
* Uninstall-Package
* Get-Package

#### Register a source

##### Register an URL to be used with DockerEngineProvider
	Register-PackageSource -ProviderName DockerEngineProvider -Name AlternateSource -Location https://contoso.com/metaData.json

##### Enlist all the registered sources
	Get-PackageSource -ProviderName DockerEngineProvider

#### Search a Docker installer 

##### Example 1: Find the latest version of all available Docker installers. 
	Find-Package –providerName DockerEngineProvider
   
##### Example 2: Search by version, according to –RequiredVersion, -MinimumVersion, and –MaximumVersion requirements. With –AllVersions parameter, all available versions of Docker installers are returned. Without it, only the latest version is returned.
    Find-Package –providerName DockerEngineProvider –AllVersions

#### Install docker

##### Example 1: Install the latest version of docker to the local machine.
	Install-Package -Name docker -ProviderName DockerEngineProvider -Verbose

##### Example 2: Install docker with pipeline result from the search cmdlets.	
	Find-Package –ProviderName DockerEngineProvider | Install-Package -Verbose

#### Download Docker
You can download and save Docker installer without installation, using Save-Package. This cmdlet accepts pipeline result from the search cmdlets. If you have multiple sources, please provide the source for download.

##### Example 1: Download and save Docker installer to a directory that matches the wildcard path. The latest version will be saved if you do not specify the version requirements.	
	Save-Package –ProviderName DockerEngineProvider -Name Docker -Path .\temp -MinimumVersion 1.2.3

##### Example 2: Download and save Docker installer from the search cmdlets.
	Find-package –ProviderName DockerEngineProvider | Save-Package -Path .

#### Get docker

##### Example 1: Inventory docker installation on the local machine.
	 Get-Package –ProviderName DockerEngineProvider

#### Uninstall docker
Uninstalls Docker from the local machine.

##### Example 1: Uninstall docker from the local machine.
	Uninstall-Package -ProviderName DockerEngineProvider -Name dOcKeR -Verbose

#### Update docker
Updates current installation of docker with the requested version

##### Example 1: Update docker
	Install-Package -Name docker -ProviderName DockerEngineProvider -Verbose -Update

### Manual Steps
    Once docker is installed, you will need to restart the machine
    After the machine is restarted, docker service needs to be in the running state

### Version
0.1.0.0

### Version History

#### 0.1.0.0
	Initial release

#### 0.1.0.1
	Bug fixes

#### 0.1.0.2
	Bug fixes

#### 0.1.0.3
	Bug fixes

### Dependencies
1. Nuget binaries
2. Update: KB3176936 or latter needs to be installed on your machine