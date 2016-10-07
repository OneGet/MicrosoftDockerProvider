$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path).Replace(".Find.Tests.ps1", ".psm1")
. "$here\..\$sut"

Describe "