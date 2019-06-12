# This PowerShell module was released under the Ms-PL license
# http://www.opensource.org/licenses/ms-pl.html
# This script was originally intended for use with Microsoft Dynamics AX 2012
# and maintained and distributed as a project on CodePlex
# http://dynamicsaxbuild.codeplex.com

# If you're using Powershell 2.0, you have to import the module before using.
# Please refer to Importing Modules: http://msdn.microsoft.com/en-us/library/dd878284%28v=vs.85%29.aspx for details.

#[int]$global:AxVersionPreference = 5

[string]$cilLogFileName = 'Dynamics.Ax.Application.dll.log'

#region Custom types
Add-Type @'
public enum XppCompileType
{
    Auto,
    Native,
    AxBuild
}
'@ 
#endregion

#region Cmdlets
Function Compile-AXIL
{
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
        
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
    
        [string]$LogPath,
        
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference,
    
        [int]$Timeout=-1)
    #endregion
    
    try
    {
        $ax = (GetConfigFromParams $PSBoundParameters)
        
        if (!$ax)
        {
            return
        }
        
        if ($LogPath -ne '')
        {
            if ($ax.IsAosRemote)
            {
                #TODO: support remote AOS
                Write-Warning "We currently don't copy CIL log from remote computers. Run the script on the AOS to get the log."
            }
            else
            {
                $doLog = $true
            }
        }		
        
        if ($doLog)
        {
            $cilLog = (Join-Path $ax.AosBinDir "XppIL\$cilLogFileName")
            if (Test-Path $cilLog)
            {
                rm $cilLog -ErrorAction SilentlyContinue
            }
        }
        
        $processParams = $PSBoundParameters
        [void]$processParams.Remove('ConfigName')
        [void]$processParams.Remove('ConfigPath')		
        
        RunAxClientAndWait -InputObject $ax -ArgumentList (StartupCmd 'CompileIL') @processParams
        
        if ($doLog)
        {
            cp $cilLog $LogPath -ErrorAction SilentlyContinue
        }
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }	
}
Function Compile-AXXpp
{
    <#
        .SYNOPSIS
        Compiles Dynamics AX application.
    #>
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
        
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
    
        [string]$LogPath,
        
        [XppCompileType]$Type = [XppCompileType]::Auto,
    
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference,
    
        [int]$Timeout=-1)
    #endregion
    
    try
    {
        $ax = (GetConfigFromParams $PSBoundParameters)
        
        if (!$ax)
        {
            return
        }
        
        switch ($Type)
        {
            Auto
            {
                if ($ax.Version -eq 6)
                {
                    $useAxBuild = $true
                }
                continue
            }
            AxBuild
            {
                if ($ax.Version -ne 6)
                {
                    throw "AxBuild can be used with AX 2012 only."
                }
                $useAxBuild = $true
                continue
            }
        }

        if ($useAxBuild)
        {
            if ($ax.IsAosRemote)
            {
                Write-Warning "AxBuild on remote servers is not currently supported. Falling back to the native compilation."
                $useAxBuild = $false
            }
            else
            {
                $aosBin = $ax | select -expand AosBinDir
                $axbuild = (Join-Path $aosBin 'AXBuild.exe')
                
                if ((Test-Path $axbuild))
                {
                    RunAxBuild $ax
                    $compiled = $true
                }
                else
                {
                    Write-Warning "AxBuild wasn't found. Falling back to the native compilation."
                    $useAxBuild = $false
                }
            }
        }
    
        if (!$compiled)
        {
            $processParams = $PSBoundParameters
            [void]$processParams.Remove('ConfigName')
            [void]$processParams.Remove('ConfigPath')		
            [void]$processParams.Remove('Type')
            
            RunAxClientAndWait -InputObject $ax -ArgumentList (StartupCmd 'CompileAll') @processParams
        }
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
Function Get-AXConfig
{
    <#
        .SYNOPSIS
        Gets Dynamics AX client configuration details.
        
        .DESCRIPTION
        Gets details about a particular Dynamics AX client configuration.
        To retrieve information about server components (AOS, database) too, use the IncludeServer parameter.
        
        Use the List parameter to get all configuration names from Windows registry.
        
        .PARAMETER ConfigName
        Specifies Dynamics AX client configuration name saved in Windows registry. If not specified, the active configuration
        is used.
        
        .PARAMETER ConfigPath
        Specifies Dynamics AX client configuration file (.axc).	
        
        .PARAMETER List
        Gets configuration names and statuses from Windows registry.
        
        .PARAMETER IncludeServer
        Returns also server-side properties, e.g. database name. If AOS is on a remote machine, you may be asked for 
        user credentials.
        
        .PARAMETER Credential
        Specifies user credentials for connection to a remote AOS, if the IncludeServer parameter is used.
        
        .PARAMETER AxVersion
        Specifies major Dynamics AX version number (e.g. 5).
        
        .LINK
        Set-AXConfig
    #>
    
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="Name",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="Name")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
        
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="Path")]
        [Alias("Path")]
        [string]$ConfigPath,
        
        [Parameter(ParameterSetName="List")]
        [switch]$List,
        
        [Parameter(ParameterSetName="Name")]
        [Parameter(ParameterSetName="Path")]
        [Alias("Server")]
        [switch]$IncludeServer,
        
        [Parameter(ParameterSetName="Name")]
        [Parameter(ParameterSetName="Path")]
        [System.Management.Automation.PSCredential]$Credential=[System.Management.Automation.PSCredential]::Empty,
        
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference)
    #endregion
    
    try
    {
        switch ($PsCmdlet.ParameterSetName)
        {
            "List" #List configurations
            {
                $rootKey = "HKCU:\SOFTWARE\Microsoft\Dynamics"
                
                [array]$versions
                if ($AxVersion)
                {
                    $versions = NormalizeAxVersionWithDot $AxVersion
                }
                else
                {
                    if (Test-Path $rootKey)
                    {
                        $versions = ls $rootKey | select -ExpandProperty PSChildName
                    }
                }

                foreach ($v in $versions)
                {
                    $regPath = "HKCU:\SOFTWARE\Microsoft\Dynamics\$v\Configuration"
                    if (Test-Path $regPath)
                    {
                        $activeConfig = Get-ItemProperty $regPath | Select -Expand Current
                        [array]$configs += ls $regPath | select `
                                            @{Name="Name"; Expression={$_.PSChildName}}, `
                                            @{Name="Version"; Expression={$v}}, `
                                            @{Name="Active"; Expression={$_.PSChildName -eq $activeConfig}}
                    }
                }
                
                return $configs
            }
            "Name" #Load configuration from Windows registry
            {
                if ($ConfigName)
                {
                    [array]$configs = Get-AXConfig -List | ? {$_.Name -eq $ConfigName}
                    
                    switch ($configs.Length)
                    {
                        0 { throw "Configuration '$ConfigName' does not exist in Windows registry." }
                        1
                        {
                            $AxVersion = $configs[0] | select -Expand Version
                        } 
                        default
                        {
                            if ($AxVersion)
                            {
                                $c = $configs | ? {$_.Version -eq (NormalizeAxVersionWithDot $AxVersion)}
                                if ($c)
                                {
                                    # Do nothing - both config name and version have been set.
                                }
                                else
                                {
                                    throw "Configuration '$ConfigName' does not exist for version $AxVersion."
                                }
                            }
                            else
                            {
                                throw "Configuration '$ConfigName' occurs multiple times (for different versions). Specify a version by -AxVersion parameter."
                            }
                        }
                    }
                }
                else
                {
                    [array]$configs = Get-AXConfig -List -AxVersion $AxVersion | ? {$_.Active}
                    
                    switch ($configs.Length)
                    {
                        0 { throw "No active configuration found in Windows registry." }
                        1
                        {
                            $ConfigName = $configs[0] | select -Expand Name
                            $AxVersion = $configs[0] | select -Expand Version
                        }
                        default
                        {
                            throw "Multiple active configuration exist (for different versions). Specify a version by -AxVersion parameter."
                        }
                    }
                    
                    if (!$ConfigName)
                    {
                        throw "No configuration found"
                    }
                }
                $registryPath = "HKCU:\SOFTWARE\Microsoft\Dynamics\{0}\Configuration\{1}" -f (NormalizeAxVersionWithDot $AxVersion), $ConfigName
                
                if (!(Test-Path $registryPath))
                {
                    throw "Configuration '$ConfigName' does not exist in Windows registry."
                }
                
                $aosDefinitionString = Get-ItemProperty $registryPath | Select -ExpandProperty aos2
                $clientBinDir = Get-ItemProperty $registryPath | Select -ExpandProperty binDir
                $clientLogDir = Get-ItemProperty $registryPath | Select -ExpandProperty logDir
                
                $properties = @{
                    ConfigName = $ConfigName
                    ClientBinDir = $clientBinDir
                    ClientLogDir = $clientLogDir
                }
                break
            }
            "Path" 	#Load configuration from file
            {
                $ConfigPath = [Management.Automation.WildcardPattern]::Escape($ConfigPath)
                
                if (!(Test-Path $ConfigPath))
                {
                    throw New-Object System.Management.Automation.ItemNotFoundException "Configuration '$ConfigPath' does not exist."
                }
                
                $aosDefinitionString = ExtractConfigTextProperty $ConfigPath 'aos2'
                $clientBinDir = (ExtractConfigTextProperty $ConfigPath 'bindir')
                $clientLogDir = (ExtractConfigTextProperty $ConfigPath 'logdir')
                
                $properties = @{
                    ClientBinDir = $clientBinDir
                    ClientLogDir = $clientLogDir
                    FilePath = $ConfigPath
                }
                
                if ($IncludeServer)
                {
                    [int]$AxVersion = (GetClientVersion $clientBinDir)
                }				
                break
            }
        }
        
        #Take first AOS only
        [string]$aosFullName = $AosDefinitionString.Split(";") | select -First 1
        $aosName, $aosComputerName, $aosPort = SplitAXAosName $aosFullName
        $isRemote = $aosComputerName -ne $Env:COMPUTERNAME
        
        $properties.Add('AosComputerName', $aosComputerName);
        $properties.Add('AosName', $aosName);
        $properties.Add('AosPort', $aosPort);
        $properties.Add('IsAosRemote', $isRemote);		
        $properties.Add('Version', $AxVersion);
        
        $configObj = New-Object PSObject -Property $Properties
        
        if ($IncludeServer)
        {
            $properties += (GetAosDetails $properties -Credential $Credential)
        }

        $o = New-Object PSObject 
        # Sort properties
        foreach($p in $properties.GetEnumerator() | Sort-Object Key)
        {
            $o | add-member Noteproperty $p.Key $p.Value
        }

        return $o
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
Function Restart-AXAOS
{
    <#
        .SYNOPSIS
        Restart Dynamics AX AOS service.	
        
        .DESCRIPTION
        Restarts the  Windows services of Microsoft Dynamics AX Application Object Server (AOS)
        on a local or remote computer. The command waits until restarting is finished.
        
        .PARAMETER ConfigName
        Specifies Dynamics AX client configuration name pointing to AOS to restart.	
        
        .PARAMETER ConfigPath
        Specifies Dynamics AX client configuration file (.axc) pointing to AOS to restart.		
        
        .PARAMETER AxVersion
        Specifies major Dynamics AX version number (e.g. 5).
    #>
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
    
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
        
        [System.Management.Automation.PSCredential]$Credential=[System.Management.Automation.PSCredential]::Empty,
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference)
    #endregion
    try
    {
        RunAosCommand -Action "Restart" @PSBoundParameters
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
Function Set-AXConfig
{
    <#
        .SYNOPSIS
        Sets active client configuration.
        
        .DESCRIPTION
        Sets active configuration used by Dynamics AX client in Windows registry.
        
        .PARAMETER ConfigName
        Specifies AX configuration name. It must already exist in Window registry.
        
        .PARAMETER AxVersion
        Specifies major Dynamics AX version number (e.g. 5).
        
        .LINK
        Get-AXConfig
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    Param(
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [Parameter(Mandatory=$true)]
        [string]$ConfigName,
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference
    )
    try
    {
        $ConfigName = [Management.Automation.WildcardPattern]::Escape($ConfigName)
        $configs = Get-AXConfig -List -AxVersion $AxVersion -ErrorAction Stop
        $config = $configs | ?{$_.Name -eq $ConfigName}
        if (!$config)
        {
            throw New-Object System.Management.Automation.ItemNotFoundException "Configuration '$ConfigName' does not exist."
        }
        if ($config.Active -eq $true)
        {
            Write-Verbose "Configuration '$ConfigName' is already active."	
        }
        else
        {
            $configPath = "HKCU:\SOFTWARE\Microsoft\Dynamics\$AxVersion.0\Configuration"
            Set-ItemProperty -Path $configPath -Name Current -Value $ConfigName
            Write-Verbose "Active configuration changed to '$ConfigName'."			
        }
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
Function Start-AXAOS
{
    <#
        .SYNOPSIS
        Start Dynamics AX AOS service.	
        
        .DESCRIPTION
        Starts the  Windows service of Microsoft Dynamics AX Application Object Server (AOS)
        on a local or remote computer. The command waits until restarting is finished.
        
        .PARAMETER ConfigName
        Specifies Dynamics AX client configuration name pointing to AOS to start.	
        
        .PARAMETER ConfigPath
        Specifies Dynamics AX client configuration file (.axc) pointing to AOS to start.		
        
        .PARAMETER AxVersion
        Specifies major Dynamics AX version number (e.g. 5).
    #>
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
    
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
        
        [System.Management.Automation.PSCredential]$Credential=[System.Management.Automation.PSCredential]::Empty,
        
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference)
    #endregion
    try
    {
        RunAosCommand -Action "Start" @PSBoundParameters
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
Function Start-AXClient
{
    <#
        .SYNOPSIS
        Starts Dynamics AX client.
        
        .DESCRIPTION
        Starts Dynamics AX client. You can specify configuration to be used
        and parameters for AX client process.
        
        .PARAMETER ConfigName
        Specifies Dynamics AX client configuration name.	
        
        .PARAMETER ConfigPath
        SpecifiesDynamics AX client configuration file (.axc).
        
        .PARAMETER Development
        If specified, the development workspace will be opened.
        
        .PARAMETER Layer
        Specifies AX layer, e.g. USR.
        
        .PARAMETER StartupCmd
        Runs a startup command (implemented by SysStartupCmd class in Dynamics AX).

        .PARAMETER PassThru
        If specified, the process instance will be returned.

        .PARAMETER Wait
        Waits for the process to complete.
    #>
        
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="Name",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="Name")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
        
        [Parameter(Position=0,
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="Path")]
        [Alias("Path")]
        [string]$ConfigPath,
        
        [Parameter(Position=0,
            Mandatory=$true,
            ValueFromPipeline=$true,
            ParameterSetName="InputObject")]
        [PSObject]$InputObject,
    
        [Parameter(Position=1)]
        [string[]]$ArgumentList,
        
        [string]$LogPath,
        [switch]$Development,
        [string]$Layer,
        [string]$StartupCmd,
        [switch]$PassThru,
        [switch]$LazyLoading,
        [switch]$NoModalBoxes,
        [switch]$Wait,
        
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference)
    #endregion

    try
    {
        switch ($PsCmdlet.ParameterSetName)
        {
            "Name"
            {
                $ax = Get-AXConfig -ConfigName $ConfigName -AxVersion $AxVersion
            }
            "Path"
            {
                $ax = Get-AXConfig -ConfigPath $ConfigPath -AxVersion $AxVersion
            }
            "InputObject"
            {
                #TODO: validation?
                $ax = $InputObject
            }
        }
        
        if ($ax -eq $null) { return }
        
        #region Set arguments
    
        if ($ax.FilePath)
        {
            $ArgumentList += "`"$($ax.FilePath)`""
        }
        else
        {
            $ArgumentList += "`"-regconfig=$($ax.ConfigName)`""
        }		
        
        if ($Development)
        {
            $ArgumentList += "-development"
        }
        if ($Layer)
        {
            $ArgumentList += "-aol=$Layer"
        }
        if ($StartupCmd)
        {
            $ArgumentList += "-startupCmd=$StartupCmd"
        }
        if ($LazyLoading)
        {
            $ArgumentList += "-lazyclassloading"
            $ArgumentList += "-lazytableloading"
        }
        if ($LogPath)
        {
            $ArgumentList += "`"-logdir=$LogPath`""
        }	
        if ($NoModalBoxes)
        {
            $ArgumentList += "-internal=noModalBoxes"				
        }
        #endregion

        if ($PsCmdlet.ShouldProcess("$ArgumentList", "Start Dynamics AX client"))
        {
            if ($Wait)
            {
                RunAxClientWithConsoleOutput $ax $ArgumentList -PassThru:$PassThru -Verbose:$VerbosePreference
            }
            else
            {
                Start-Process (Join-Path $ax.ClientBinDir "ax32.exe") -ArgumentList $ArgumentList -PassThru:$PassThru -Verbose:$VerbosePreference
            }
        }
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }	
}

Function Stop-AXAOS
{
    <#
        .SYNOPSIS
        Stop Dynamics AX AOS service.	
        
        .DESCRIPTION
        Stops the  Windows services of Microsoft Dynamics AX Application Object Server (AOS)
        on a local or remote computer. The command waits until restarting is finished.
        
        .PARAMETER ConfigName
        Specifies Dynamics AX client configuration name pointing to AOS to stop.	
        
        .PARAMETER ConfigPath
        Specifies Dynamics AX client configuration file (.axc) pointing to AOS to stop.		
        
        .PARAMETER AxVersion
        Specifies major Dynamics AX version number (e.g. 5).
    #>
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
    
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
        
        [System.Management.Automation.PSCredential]$Credential=[System.Management.Automation.PSCredential]::Empty,
        
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference)
    #endregion
    
    try
    {
        RunAosCommand -Action "Stop" @PSBoundParameters
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
Function Synchronize-AXDatabase
{
    <#
        .SYNOPSIS
        Synchronizes Dynamics AX database.
        
        .DESCRIPTION
        Synchronizes Dynamics AX database with tables and other objects defined
        by application layer.
    #>
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
        
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
    
        [string]$LogPath,
        
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference,
    
        [int]$Timeout=-1)
    #endregion
    
    try
    {
        $ax = (GetConfigFromParams $PSBoundParameters)
        
        if (!$ax)
        {
            return
        }
        
        $processParams = $PSBoundParameters
        [void]$processParams.Remove('ConfigName')
        [void]$processParams.Remove('ConfigPath')		
        
        RunAxClientAndWait -InputObject $ax -ArgumentList (StartupCmd 'Synchronize') @processParams
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}

Function Update-AXXRef
{
    <#
        .SYNOPSIS
        Updates cross-references.
        
        .DESCRIPTION
        Updates cross-references between objects in Dynamics AX application.
    #>
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
        
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
    
        [string]$LogPath,
        
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference,
    
        [int]$Timeout=-1)
    #endregion

    try
    {
        $ax = (GetConfigFromParams $PSBoundParameters)
        
        if (!$ax)
        {
            return
        }
        
        $processParams = $PSBoundParameters
        [void]$processParams.Remove('ConfigName')
        [void]$processParams.Remove('ConfigPath')		
        
        RunAxClientAndWait -InputObject $ax -ArgumentList (StartupCmd 'xRefAll') @processParams
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
Function Update-AXXRefIndex
{
    <#
        .SYNOPSIS
        Rebuilds database indexes for Dynamics AX tables related to cross-references.
        
        .DESCRIPTION
        Rebuilds indexes in SQL Server database for Dynamics AX tables. Only tables related
        to cross-reference functionality are affected.
        
        Index rebuild may improve performance of cross-reference functionality.
    #>
    
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [ValidatePattern('^[^\\]*$')]
        [Alias("Name")]
        [string]$ConfigName,
        
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
    
        [Alias("Version")]
        [int]$AxVersion=$AxVersionPreference,
    
        [int]$Timeout=[UInt16]::MaxValue)
    #endregion
    
    try
    {
        if (!(CheckAndAddSqlSnapin))
        {
            throw "SQL Server snappin could not be loaded."
        }

        if ($Timeout -le 0)
        {
            $Timeout = [UInt16]::MaxValue
        }

        $PSBoundParameters.Remove("Timeout") | Out-Null
        $ax = Get-AXConfig -IncludeServer @PSBoundParameters
        
        if ($PsCmdlet.ShouldProcess("Server $($ax.DatabaseServer), DB $($ax.Database)", "Update statistics for xRef tables"))
        {
            Invoke-Sqlcmd -ServerInstance $ax.DatabaseServer -Database $ax.Database -QueryTimeout $Timeout `
                        -Query "EXEC sp_Msforeachtable @command1 ='ALTER INDEX ALL ON ? REBUILD', @whereand = 'and o.name like `"xRef%`"'" 
        }
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
    
}
#endregion

#region Helper methods
Function CheckAndAddSqlSnapin
{
    #Returns true if SQL Snapin is ready, false otherwise.
    #Adds the snapin if needed.
    
    $sqlSnapinName = 'SqlServerCmdletSnapin*'
    #If SQL Server snap-in is not loaded	
    if (!(Get-PSSnapin | ?{$_.Name -like $sqlSnapinName}))
    {
        #If snappin found
        if (Get-PSSnapin -Registered | ?{$_.Name -like $sqlSnapinName})
        {
            Add-PSSnapin $sqlSnapinName
        }
        else
        {
            return $false
        }
    }
    return $true;
}
Function CommonParams
{
    Param(
        [Parameter(Mandatory=$true)]
        [HashTable] $params
    )

    $names = 'Debug', 'ErrorAction', 'ErrorVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', `
        'Verbose', 'WarningAction', 'WarningVariable', 'WhatIf', 'Confirm' 

    $common = @{}
        
    $names.GetEnumerator() | ForEach-Object `
    {
        if ($params.ContainsKey($_))
        {
            $common.Add($_, $params[$_])
        }		
    }	
    
    return $common	
}
Function ExtractConfigTextProperty
{
    <#
        .SYNOPSIS
        Extracts a single text property from .axc file.
    #>
    
    Param(
        [Parameter(Mandatory=$true)]
        [Alias("Path")]
        [string]$ConfigPath,
        [Parameter(Mandatory=$true)]
        [string]$Property
    )
    
    $line = (Select-String $ConfigPath -Pattern " *$Property,Text," -List).Line
    if (!$line)
    {
        throw "Property $Property was not found in the configuration file"
    }
    $line = $line.Trim()
    $line.Substring($Property.Length + ",Text,".Length)
}
Function GetAosCommandProvider
{
    Param([string]$Action)
    
    switch ($Action)
    {
        "Start"
        {
            @{
                Description = "Start AOS"
                Command = {param($ServiceName) Start-Service -Name $ServiceName}
            }	
        }
        "Stop"
        {
            @{
                Description = "Stop AOS"
                Command = {param($ServiceName) Stop-Service -Name $ServiceName}				
            }
        }
        "Restart"
        {
            @{
                Description = "Restart AOS"
                Command = {param($ServiceName) Restart-Service -Name $ServiceName}			
            }
        }
    }
}
Function GetAosDetails
{
    #If multiple AOSes are defined in AX configuration, just the first one is used
    Param(
        [Parameter(Mandatory=$true)]
        $Config,
        [string]$AosDefinitionString,
        [System.Management.Automation.PSCredential]$Credential=[System.Management.Automation.PSCredential]::Empty
    )	
    
    #region ScriptBlock
    $scriptBlock = {
        Param($AosPort,
            $AxVersion)
        
        #region ConvertAosPortToAosNumber
        $origLocation = Get-Location
        cd "HKLM:\SYSTEM\CurrentControlSet\services\Dynamics Server\$AxVersion.0"
        $aosNumber = ls | ? -FilterScript {(Get-ItemProperty (Join-Path $_.PSChildName (Get-ItemProperty -Path $_.PSChildName |
            Select -ExpandProperty Current))).Port -eq $AosPort} | select -ExpandProperty PSChildName
        cd $origLocation
        #endregion
        
        $pathToAosKey = "HKLM:\SYSTEM\CurrentControlSet\services\Dynamics Server\$AxVersion.0\$aosNumber"
        
        $aosActiveConfig = Get-ItemProperty $pathToAosKey | Select -ExpandProperty Current
        $currentProperties = Get-ItemProperty (Join-Path $pathToAosKey $aosActiveConfig)
        
        $applRootDir = ($currentProperties | Select -ExpandProperty directory)
        $applName = ($currentProperties | Select -ExpandProperty application)
        $applDir = "$applRootDir\Appl\$applName"        
        
        $aosBinDir = $currentProperties | Select -ExpandProperty bindir
        $dbserver = $currentProperties | Select -ExpandProperty dbserver
        $dbname = $currentProperties | Select -ExpandProperty database
        $aosLogDir = $currentProperties | Select -ExpandProperty logdir
        $aosServiceName = ("AOS$($AxVersion)0`${0:D2}" -f $aosNumber)
        $aosServiceAccount = Get-WmiObject win32_service | ? {$_.Name -eq $aosServiceName} | select -expand StartName

        $data = @{
            AosBinDir = $aosBinDir
            AosNumber = $aosNumber
            AosLogDir = $aosLogDir
            AosServiceAccount = $aosServiceAccount
            AosServiceName = $aosServiceName
            ApplDir = $applDir 
            ApplName = $applName
            DatabaseServer = $dbserver
            Database = $dbname
        }
        
        if (($currentProperties | Get-Member | Select-Object –ExpandProperty Name) –contains 'hotswapenabled')
        {
            [bool]$hotswap = ($currentProperties | Select -ExpandProperty 'hotswapenabled') -as [int]
            $data.Add('HotSwapEnabled', $hotswap)
        }
        
        $data
    }
    #endregion
    
    if ($Config.IsAosRemote)
    {
        Invoke-Command -ComputerName $Config.AosComputerName -Credential $Credential -ScriptBlock $scriptBlock -ArgumentList $Config.AosPort, $Config.Version
    }
    else
    {
        & $scriptBlock -AosPort $Config.AosPort -AxVersion $Config.Version
    }
}
Function GetClientVersion
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$clientBinDir
    )
    
    $fullVersion = (Get-Command (Join-Path $clientBinDir 'ax32.exe')).FileVersionInfo.ProductVersion
    return $fullVersion.Substring(0,1) -as [int]
}
Function NormalizeAxVersionWithDot
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$inputVersion
    )
        
    switch -regex ($inputVersion)
    {
        "^\d\.\d$" { return $inputVersion }
        "^\d$" { return "$inputVersion.0" }
        default { throw "$inputVersion is not a valid version of Dynamics AX." }
    }
}
Function GetConfigFromParams([HashTable]$params)
{
    $commonParams = CommonParams($params)
    
    if ($params['ConfigPath'])
    {
        return Get-AXConfig -IncludeServer -Path  $ConfigPath @commonParams
    }
    else
    {
        return Get-AXConfig -IncludeServer -Name $ConfigName @commonParams
    }
}
Function RunAosCommand
{
    #region Parameters
    [CmdletBinding(
        DefaultParameterSetName="ConfigName",
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Position=0,
            ParameterSetName="ConfigName")]
        [Alias("Name")]
        [string]$ConfigName,
    
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            ParameterSetName="ConfigPath")]
        [Alias("Path")]
        [string]$ConfigPath,
        
        [ValidateSet("Start", "Stop", "Restart")]
        [string]$Action="Restart",

        [System.Management.Automation.PSCredential]$Credential=[System.Management.Automation.PSCredential]::Empty,
        
        [int]$AxVersion=$AxVersionPreference)
    #endregion

    $commandData = GetAosCommandProvider $Action
    
    $PSBoundParameters.Remove("Action") | Out-Null
    $axData = Get-AXConfig -IncludeServer @PSBoundParameters
    $serviceName = $axData.AosServiceName
    
    if ($axData.IsAosRemote)
    {
        if ($PsCmdlet.ShouldProcess("$serviceName ($($axData.AosComputerName))", $commandData.Description))
        {
            Invoke-Command -ScriptBlock $commandData.Command -ArgumentList $serviceName `
                -ComputerName $axData.AosComputerName -Credential $Credential 
        }
    }
    else
    {
        switch ($Action)
        {
            "Start" {Start-Service -Name $ServiceName}
            "Stop" {Stop-Service -Name $ServiceName}
            "Restart" {Restart-Service -Name $ServiceName}
        }
    }
}

Function RunAxBuild
{
    #region Parameters
    [CmdletBinding(
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true)]
        [PSObject]$ax)
        
    $aosBin = $ax | select -expand AosBinDir
    $axbuild = (Join-Path $aosBin 'AXBuild.exe')
    $clientBin = $ax | select -expand ClientBinDir
    $axServer = (Join-Path $aosBin 'ax32serv.exe')
    
    if ($ax.HotSwapEnabled -eq $true)
    {
        Write-Warning "Hot-swapping of assemblies is enabled on the AOS. AxBuild compilation may return wrong results."
    }
    
    if ($PsCmdlet.ShouldProcess($ax.Database, "AxBuild"))
    {
        $parameters = 'xppcompileall', "`"/compiler=$axServer`"", "/s=$($ax.AosNumber)", "`"/altbin=$clientBin`"", "`"/log=$LogPath`"", "`"/layer=var`""
        & $axbuild $parameters
    }
}

Function RunAxClientAndWait
{
    #region Parameters
    [CmdletBinding(
        SupportsShouldProcess=$true)]
    Param(
        [Parameter(Mandatory=$true)]
        [PSObject]$InputObject,

        [Alias("Arguments")]
        [string[]]$ArgumentList,
        
        [string]$LogPath,
        
        [int]$Timeout=-1,
        
        [Alias("tm")]
        [string]$TimeoutMessage = "Timeout expired. Operation was unable to complete in $Timeout seconds.")
    #endregion
    if ($Timeout -ge 0)
    {
        $timeoutMiliseconds = $Timeout * 1000;
    }
    else #Accept all negative numbers, change them to -1 expected by WaitForExit()
    {
        $timeoutMiliseconds = -1
    }
    
    $PSBoundParameters.Remove("Timeout") | Out-Null
    $PSBoundParameters.Remove("TimeoutMessage") | Out-Null
    
    $startTime = Get-Date 
    $process = Start-AxClient -PassThru -LazyLoading -NoModalBoxes @PSBoundParameters -ErrorAction "Stop"

    if ($process -and !$WhatIfPreference)
    {
        if ($Timeout -ge 0)
        {
            Write-Verbose "Waiting for process to finish (timeout $Timeout seconds)."
        }
        else
        {
            Write-Verbose "Waiting for process to finish (no timeout)."
        }
        if (!$process.WaitForExit($timeoutMiliseconds))
        {
            $process.Kill()
            $process.Close();
            throw New-Object System.TimeoutException $TimeoutMessage
        }
        $process.Close();
        Write-Verbose "Process finished."

        #Look whether any connection error occured (AX seems not to return ExitCode)
        $eventsAfter = $startTime.Subtract((New-TimeSpan -Seconds 1)) #Remove one second to see events occured in the same second when process started
        $lastErrorMsg = Get-EventLog -LogName "Application" -Source "Microsoft Dynamics AX" -EntryType "Error" -InstanceId 110 `
            -After ($eventsAfter) -ErrorAction Ignore | select -expand ReplacementStrings -First 1 | where {$_}
        
        if ($lastErrorMsg)
        {
            throw $lastErrorMsg
        }
    }
}

<#
        .SYNOPSIS
        Runs AX client and show console output.
        
        .DESCRIPTION
        Runs Dynamics AX client, waits for process to exit and shows messages
        from output and error console streams.
    #>
Function RunAxClientWithConsoleOutput()
{
    #region Parameters
    [CmdletBinding(
        SupportsShouldProcess=$true)]
    Param(
        $AxConfig,
        [string[]]$ArgumentList,
        [switch]$PassThru)
    #endregion
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo.FileName = (Join-Path $AxConfig.ClientBinDir "ax32.exe")
    $process.StartInfo.Arguments = $ArgumentList
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true

    Function GetAxMessages
    {
        Get-Event -SourceIdentifier AxOutput -ErrorAction SilentlyContinue | %{
            if ($_.SourceEventArgs.Data)
            {
                $_.SourceEventArgs.Data
            }
            Remove-Event -EventIdentifier $_.EventIdentifier
        }
        
        Get-Event -SourceIdentifier AxError -ErrorAction SilentlyContinue | %{
            if ($_.SourceEventArgs.Data)
            {
                Write-Error $_.SourceEventArgs.Data
            }
            Remove-Event -EventIdentifier $_.EventIdentifier
        }
    }
                    
    try
    {
        Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -SourceIdentifier AxOutput
        Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -SourceIdentifier AxError

        $process.Start() | Out-Null
        if ($PassThru)
        {
            $process
        }
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        while (!$process.WaitForExit(1000))
        {
            GetAxMessages	
        }
        $process.WaitForExit()
        GetAxMessages
    }
    finally
    {
        $process.Close()
        Get-EventSubscriber -SourceIdentifier AxOutput -ea SilentlyContinue | Unregister-Event
        Get-EventSubscriber -SourceIdentifier AxError -ea SilentlyContinue | Unregister-Event
    }
}

Function SplitAXAosName
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$AosFullName
    )
    if ($AosFullName.Contains('@'))
    {
        $aosName, $computerNameAndPort = $AosFullName.Split("@")
    }
    else
    {
        $computerNameAndPort = $AosFullName
    }
    $computerName, $port = $computerNameAndPort.Split(":")
    return $aosName, $computerName, $port
}
Function StartupCmd([string]$cmd)
{
    "-startupCmd=$cmd"
}
#endregion
