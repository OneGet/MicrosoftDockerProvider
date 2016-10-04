
#########################################################################################
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# SaveHTTPItemUsingBITS
#
#########################################################################################

function Save-HTTPItemUsingBitsTransfer
{
    [CmdletBinding()]
    param(
       [Parameter(Mandatory=$true)]
       $Uri,
       [Parameter(Mandatory=$true)]
       $Destination
    )

    begin
    {
        $fullUri = [Uri]$Uri
        if (($fullUri.Scheme -ne 'http') -and ($fullUri.Scheme -ne 'https'))
        {
            throw "Uri: $uri is not supported. Only http or https schema are supported."
        }
    }
    
    end
    {
        $jstate = $null
        [bool] $isTransferCompleted = $false
        try
        {
            $mycurrentPath = $script:MyInvocation.MyCommand.Path
            $myCurrentDirectory = Split-Path $mycurrentPath
            $bitsCommandPath = join-path $myCurrentDirectory "BitsOnNano.exe"
            $jobNameTemp = "SH{0}" -f (get-date).Ticks
            $output = & $bitsCommandPath -Start-Transfer  -DisplayName $jobNameTemp -Source $Uri -Destination $Destination
            $le = $lastexitcode
            
            do
            {
                $jname,$jid,$jstate,$jbytesTransferred,$jbytesTotal,$null = $output -split ":"
                
                if ( (@("BG_JOB_STATE_ERROR", "BG_JOB_STATE_TRANSIENT_ERROR", "BG_JOB_STATE_CANCELLED") -contains $jstate) -or ($le))
                {
                    & $bitsCommandPath -Stop-Transfer -ID $jid | Out-Null

                     throw "Save-HTTPItem: Bits Transfer failed. Job State: $jstate ExitCode = $le"
                }
                
                if (@("BG_JOB_STATE_TRANSFERRED") -contains $jstate)
                {
                    & $bitsCommandPath -Remove-Transfer -ID $jid | Out-Null
                    $isTransferCompleted = $true
                    break;
                }

                Start-Sleep -Seconds 1
                $output = & $bitsCommandPath -Get-TransferStatus -ID $jid
                $le = $lastExitCode
            }while($true);
        }
        finally
        {
            if ((-not $jstate)  -and (-not $isTransferCompleted))
            {
               "CleanUp:"
               & $bitsCommandPath -Stop-Transfer -ID $jid | Out-Null
            }
        }        
    }
}
