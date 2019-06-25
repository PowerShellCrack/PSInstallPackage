
##*===========================================================================
##* FUNCTIONS
##*===========================================================================
Function Test-IsISE {
    # try...catch accounts for:
    # Set-StrictMode -Version latest
    try {    
        return ($null -ne $psISE);
    }
    catch {
        return $false;
    }
}

Function Get-ScriptPath {
    # Makes debugging from ISE easier.
    if ($PSScriptRoot -eq "")
    {
        if (Test-IsISE)
        {
            $psISE.CurrentFile.FullPath
            #$root = Split-Path -Parent $psISE.CurrentFile.FullPath
        }
        else
        {
            $context = $psEditor.GetEditorContext()
            $context.CurrentFile.Path
            #$root = Split-Path -Parent $context.CurrentFile.Path
        }
    }
    else
    {
        #$PSScriptRoot
        $PSCommandPath
        #$MyInvocation.MyCommand.Path
    }
}


Function Get-SMSTSENV{
    param(
        [switch]$ReturnLogPath,
        [switch]$NoWarning
    )
    
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    }
    Process{
        try{
            # Create an object to access the task sequence environment
            $Script:tsenv = New-Object -COMObject Microsoft.SMS.TSEnvironment 
        }
        catch{
            If(${CmdletName}){$prefix = "${CmdletName} ::" }Else{$prefix = "" }
            If(!$NoWarning){Write-Warning ("{0}Task Sequence environment not detected. Running in stand-alone mode" -f $prefix)}
            
            #set variable to null
            $Script:tsenv = $null
        }
        Finally{
            #set global Logpath
            if ($Script:tsenv){
                #grab the progress UI
                $Script:TSProgressUi = New-Object -ComObject Microsoft.SMS.TSProgressUI

                # Convert all of the variables currently in the environment to PowerShell variables
                $tsenv.GetVariables() | ForEach-Object { Set-Variable -Name "$_" -Value "$($tsenv.Value($_))" }
                
                # Query the environment to get an existing variable
                # Set a variable for the task sequence log path
                
                #Something like: C:\MININT\SMSOSD\OSDLOGS
                #[string]$LogPath = $tsenv.Value("LogPath")
                #Somthing like C:\WINDOWS\CCM\Logs\SMSTSLog
                [string]$LogPath = $tsenv.Value("_SMSTSLogPath")
                
            }
            Else{
                [string]$LogPath = $env:Temp
            }
        }
    }
    End{
        #If output log path if specified , otherwise output ts environment
        If($ReturnLogPath){
            return $LogPath
        }
        Else{
            return $Script:tsenv
        }
    }
}


Function Format-ElapsedTime($ts) {
    $elapsedTime = ""
    if ( $ts.Minutes -gt 0 ){$elapsedTime = [string]::Format( "{0:00} min. {1:00}.{2:00} sec", $ts.Minutes, $ts.Seconds, $ts.Milliseconds / 10 );}
    else{$elapsedTime = [string]::Format( "{0:00}.{1:00} sec", $ts.Seconds, $ts.Milliseconds / 10 );}
    if ($ts.Hours -eq 0 -and $ts.Minutes -eq 0 -and $ts.Seconds -eq 0){$elapsedTime = [string]::Format("{0:00} ms", $ts.Milliseconds);}
    if ($ts.Milliseconds -eq 0){$elapsedTime = [string]::Format("{0} ms", $ts.TotalMilliseconds);}
    return $elapsedTime
}

Function Format-DatePrefix{
    [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
	[string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
    return ($LogDate + " " + $LogTime)
}

Function Write-LogEntry{
    param(
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter(Mandatory=$false,Position=2)]
		[string]$Source = '',
        [parameter(Mandatory=$false)]
        [ValidateSet(0,1,2,3,4)]
        [int16]$Severity,

        [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will written to")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputLogFile = $Global:LogFilePath,

        [parameter(Mandatory=$false)]
        [switch]$Outhost
    )
    Begin{
        [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
        [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
        [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes
        [string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
        
    }
    Process{
        # Get the file name of the source script
        Try {
            If ($script:MyInvocation.Value.ScriptName) {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
            }
            Else {
                [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
            }
        }
        Catch {
            $ScriptSource = ''
        }
        
        
        If(!$Severity){$Severity = 1}
        $LogFormat = "<![LOG[$Message]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$ScriptSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$Severity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogFormat -Append -NoClobber -Encoding Default -FilePath $OutputLogFile -ErrorAction Stop
        }
        catch {
            Write-Host ("[{0}] [{1}] :: Unable to append log entry to [{1}], error: {2}" -f $LogTimePlusBias,$ScriptSource,$OutputLogFile,$_.Exception.ErrorMessage) -ForegroundColor Red
        }
    }
    End{
        If($Outhost -or $Global:OutTohost){
            If($Source){
                $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$Source,$Message)
            }
            Else{
                $OutputMsg = ("[{0}] [{1}] :: {2}" -f $LogTimePlusBias,$ScriptSource,$Message)
            }

            Switch($Severity){
                0       {Write-Host $OutputMsg -ForegroundColor Green}
                1       {Write-Host $OutputMsg -ForegroundColor Gray}
                2       {Write-Warning $OutputMsg}
                3       {Write-Host $OutputMsg -ForegroundColor Red}
                4       {If($Global:Verbose){Write-Verbose $OutputMsg}}
                default {Write-Host $OutputMsg}
            }
        }
    }
}

function Show-ProgressStatus
{
    <#
    .SYNOPSIS
        Shows task sequence secondary progress of a specific step
    
    .DESCRIPTION
        Adds a second progress bar to the existing Task Sequence Progress UI.
        This progress bar can be updated to allow for a real-time progress of
        a specific task sequence sub-step.
        The Step and Max Step parameters are calculated when passed. This allows
        you to have a "max steps" of 400, and update the step parameter. 100%
        would be achieved when step is 400 and max step is 400. The percentages
        are calculated behind the scenes by the Com Object.
    
    .PARAMETER Message
        The message to display the progress
    .PARAMETER Step
        Integer indicating current step
    .PARAMETER MaxStep
        Integer indicating 100%. A number other than 100 can be used.
    .INPUTS
         - Message: String
         - Step: Long
         - MaxStep: Long
    .OUTPUTS
        None
    .EXAMPLE
        Set's "Custom Step 1" at 30 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 100 -MaxStep 300
    
    .EXAMPLE
        Set's "Custom Step 1" at 50 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 150 -MaxStep 300
    .EXAMPLE
        Set's "Custom Step 1" at 100 percent complete
        Show-ProgressStatus -Message "Running Custom Step 1" -Step 300 -MaxStep 300
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string] $Message,
        [Parameter(Mandatory=$true)]
        [int]$Step,
        [Parameter(Mandatory=$true)]
        [int]$MaxStep,
        [string]$SubMessage,
        [int]$IncrementSteps,
        [switch]$Outhost
    )

    Begin{

        If($SubMessage){
            $StatusMessage = ("{0} [{1}]" -f $Message,$SubMessage)
        }
        Else{
            $StatusMessage = $Message

        }
    }
    Process
    {
        If($Script:tsenv){
            $Script:TSProgressUi.ShowActionProgress(`
                $Script:tsenv.Value("_SMSTSOrgName"),`
                $Script:tsenv.Value("_SMSTSPackageName"),`
                $Script:tsenv.Value("_SMSTSCustomProgressDialogMessage"),`
                $Script:tsenv.Value("_SMSTSCurrentActionName"),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSNextInstructionPointer")),`
                [Convert]::ToUInt32($Script:tsenv.Value("_SMSTSInstructionTableSize")),`
                $StatusMessage,`
                $Step,`
                $Maxstep)
        }
        Else{
            Write-Progress -Activity "$Message ($Step of $Maxstep)" -Status $StatusMessage -PercentComplete (($Step / $Maxstep) * 100) -id 1
        }
    }
    End{
        Write-LogEntry $Message -Severity 1 -Outhost:$Outhost
    }
}


# <Your custom functions go here>
Function Get-IniFile ($file)       # Based on "http://stackoverflow.com/a/422529"
 {
    $ini = [ordered]@{}

    # Create a default section if none exist in the file. Like a java prop file.
    $section = "NO_SECTION"
    $ini[$section] = [ordered]@{}

    switch -regex -file $file 
    {    
        "^\[(.+)\]$" 
        {
            $section = $matches[1].Trim()
            $ini[$section] = [ordered]@{}
        }

        "^\s*(.+?)\s*=\s*(.*)" 
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value.Trim()
        }

        default
        {
            $ini[$section]["<$("{0:d4}" -f $CommentCount++)>"] = $_
        }
    }

    $ini
}

Function Set-IniFile ($iniObject, $Path, $PrintNoSection=$false, $PreserveNonData=$true)
{                                  # Based on "http://www.out-web.net/?p=109"
    $Content = @()
    ForEach ($Category in $iniObject.Keys)
    {
        if ( ($Category -notlike 'NO_SECTION') -or $PrintNoSection )
        {
            # Put a newline before category as seperator, only if there is none 
            $seperator = if ($Content[$Content.Count - 1] -eq "") {} else { "`n" }

            $Content += $seperator + "[$Category]";
        }

        ForEach ($Key in $iniObject.$Category.Keys)
        {           
            if ( $Key.StartsWith('<') )
            {
                if ($PreserveNonData)
                    {
                        $Content += $iniObject.$Category.$Key
                    }
            }
            else
            {
                $Content += "$Key = " + $iniObject.$Category.$Key
            }
        }
    }

    $Content | Set-Content $Path -Force
}

function Add-LoginToLocalPrivilege{
    <#
            .SYNOPSIS
    Adds the provided login to the local security privilege that is chosen. Must be run as Administrator in UAC mode.
    Returns a boolean $true if it was successful, $false if it was not.

    .DESCRIPTION
    Uses the built in secedit.exe to export the current configuration then re-import
    the new configuration with the provided login added to the appropriate privilege.

    The pipeline object must be passed in a DOMAIN\User format as string.

    This function supports the -WhatIf, -Confirm, and -Verbose switches.

    .PARAMETER DomainAccount
    Value passed as a DOMAIN\Account format.

    .PARAMETER Domain 
    Domain of the account - can be local account by specifying local computer name.
    Must be used in conjunction with Account.

    .PARAMETER Account
    Username of the account you want added to that privilege
    Must be used in conjunction with Domain

    .PARAMETER Privilege
    The name of the privilege you want to be added.

    This must be one in the following list:
    SeManageVolumePrivilege
    SeLockMemoryPrivilege

    .PARAMETER TemporaryFolderPath
    The folder path where the secedit exports and imports will reside. 

    The default if this parameter is not provided is $env:USERPROFILE

    .EXAMPLE
    Add-LoginToLocalPrivilege -Domain "NEIER" -Account "Kyle" -Privilege "SeManageVolumePrivilege"

    Using full parameter names

    .EXAMPLE
    Add-LoginToLocalPrivilege "NEIER\Kyle" "SeLockMemoryPrivilege"

    Using Positional parameters only allowed when passing DomainAccount together, not independently.

    .EXAMPLE
    Add-LoginToLocalPrivilege "NEIER\Kyle" "SeLockMemoryPrivilege" -Verbose

    This function supports the verbose switch. Will provide to you several 
    text cues as part of the execution to the console. Will not output the text, only presents to console.

    .EXAMPLE
    ("NEIER\Kyle", "NEIER\Stephanie") | Add-LoginToLocalPrivilege -Privilege "SeManageVolumePrivilege" -Verbose

    Passing array of DOMAIN\User as pipeline parameter with -v switch for verbose logging. Only "Domain\Account"
    can be passed through pipeline. You cannot use the Domain and Account parameters when using the pipeline.

    .NOTES
    The temporary files should be removed at the end of the script. 

    If there is error - two files may remain in the $TemporaryFolderPath (default $env:USERPFORILE)
    UserRightsAsTheyExist.inf
    ApplyUserRights.inf

    These should be deleted if they exist, but will be overwritten if this is run again.

    Author:    Kyle Neier
    Blog: http://sqldbamusings.blogspot.com
    Twitter: Kyle_Neier

    .ADDITIONAL
    - Removed Whatif, Confirm capabalities to make it silent
    - Removed SeManageVolumePrivilege, SeLockMemoryPrivilege choice. Allowed any security policy to be applied. Will error if misspelled; use MS article:
            https://technet.microsoft.com/en-us/library/dd349804(v=ws.10).aspx
    - Changed $TemporaryFolderPath to default to $env:Temp
    - Added SYSTEM account support
    - removed return output; added to a boolean parameter
    
    .PARAMETERS ApplyFileName
    Specify file name of the File used to apply new security policy. Default is ApplyUserRights.inf
    Use if you don't want the file to be overwritten

    .PARAMETERS ReturnOutput
    Boolean specifies if the return output is sent
    Default is enabled

    .PARAMETERS BackupSecFilePath
    Variable is Global
    If string is specified, the UserRightsAsTheyExist.inf file is copied to specified file name
    If directory is not specified $TemporaryFolderPath will be used
    This allows for restore of users rights if needed and troubleshooting
    Default is disabled
    
    .EXAMPLE 
    Add-LoginToLocalPrivilege "$runningSID,$SystemSID,$AdminGrpSID" -Privilege SeBackupPrivilege -ApplyFileName "SeBackupPrivilege.inf" -ReturnOutput $false


    Author: Richard Tracy
    Date: 05/31/2017
    #>

        #Specify the default parameterset
        [CmdletBinding(DefaultParametersetName="JointNames")]
    param
        (
    [parameter(
    Mandatory=$true, 
    Position=0,
    ParameterSetName="SplitNames")]
    [string] $Domain,

    [parameter(
    Mandatory=$true, 
    Position=1,
    ParameterSetName="SplitNames"
                )]
    [string] $Account,

    [parameter(
    Mandatory=$true, 
    Position=0,
    ParameterSetName="JointNames",
    ValueFromPipeline= $true
                )]
    [string] $DomainAccount,

    [parameter(Mandatory=$true, Position=2)]
    #[ValidateSet("SeManageVolumePrivilege", "SeLockMemoryPrivilege")]
    [string] $Privilege,

    [parameter(Mandatory=$false)]
    [string] $TemporaryFolderPath = $env:Temp,
    
    [parameter(Mandatory=$false)]
    [string] $ApplyFileName = "ApplyUserRights.inf", 
    
    [parameter(Mandatory=$false)]
    [string] $BackupSecFilePath, 

    [parameter(Mandatory=$false)]
    [boolean] $ReturnOutput = $true
    )

    $BackupSecFilePath = $Global:BackupSecFilePath
    #Determine which parameter set was used
    switch ($PsCmdlet.ParameterSetName){
        "SplitNames"{ 
            #If SplitNames was used, combine the names into a single string
            Write-Verbose "Domain and Account provided - combining for rest of script."
            $DomainAccount = "$Domain`\$Account"
        }
        "JointNames"{
            Write-Verbose "Domain\Account combination provided."
            #Need to do nothing more, the parameter passed is sufficient.
        }
    }

    #Created simple function here so I didn't have to re-type these commands
        function Remove-TempFiles{
            #Evaluate whether the ApplyUserRights.inf file exists
            if(Test-Path ($TemporaryFolderPath+"\"+$ApplyFileName)){
                #Remove it if it does.
                Write-Verbose "Removing $TemporaryFolderPath`\$ApplyFileName"
                Remove-Item ($TemporaryFolderPath+"\"+$ApplyFileName) -Force
            }
    
            #Evaluate whether the UserRightsAsTheyExists.inf file exists
            if(Test-Path "$TemporaryFolderPath\UserRightsAsTheyExist.inf"){
                #Remove it if it does.
                Write-Verbose "Removing $TemporaryFolderPath\UserRightsAsTheyExist.inf"
                If($BackupSecFilePath){
                    $BackupSecFileDir = [System.IO.Path]::GetDirectoryName("$Global:BackupSecFilePath")
                    $BackupSecFileName = [System.IO.Path]::GetFileName("$Global:BackupSecFilePath")
                    If([string]::IsNullOrEmpty($BackupSecFileDir)){
                        $Global:BackupSecFilePath = $TemporaryFolderPath+"\"+$BackupSecFileName
                    }
                    Copy-Item "$TemporaryFolderPath\UserRightsAsTheyExist.inf" "$Global:BackupSecFilePath"
                }
                Remove-Item "$TemporaryFolderPath\UserRightsAsTheyExist.inf" -Force
            }
        }
        #End Remove-TempFiles Function

    Write-Verbose "Adding $DomainAccount to $Privilege"

        Write-Verbose "Verifying that export file does not exist."
        #Clean Up any files that may be hanging around.
        Remove-TempFiles
    
    Write-Verbose "Executing secedit and sending to $TemporaryFolderPath"
        #Use secedit (built in command in windows) to export current User Rights Assignment
        $SeceditResults = secedit /export /areas USER_RIGHTS /cfg "$TemporaryFolderPath\UserRightsAsTheyExist.inf"

    #Make certain export was successful
        if($SeceditResults[$SeceditResults.Count-2] -eq "The task has completed successfully.")
    {

    Write-Verbose "Secedit export was successful, proceeding to re-import"
            #Save out the header of the file to be imported
        
    Write-Verbose "Save out header for $TemporaryFolderPath`\$ApplyFileName"
        
    "[Unicode]
    Unicode=yes
    [Version]
    signature=`"`$CHICAGO`$`"
    Revision=1
    [Privilege Rights]" | Out-File ($TemporaryFolderPath+"\"+$ApplyFileName) -Force
                                    
    #Bring the exported config file in as an array
            Write-Verbose "Importing the exported secedit file."
            $SecurityPolicyExport = Get-Content "$TemporaryFolderPath\UserRightsAsTheyExist.inf"

            #enumerate over each of these files, looking for the Perform Volume Maintenance Tasks privilege
            [Boolean]$isFound = $false
            foreach($line in $SecurityPolicyExport)
    {
    if($line -like "$Privilege`*")
    {
    Write-Verbose "Line with the $Privilege found in export, appending $DomainAccount to it"
                                #Add the current domain\user to the list
                                $line = $line + ",$DomainAccount"
                                #output line, with all old + new accounts to re-import
                                $line | Out-File ($TemporaryFolderPath+"\"+$ApplyFileName) -Append
                            
    $isFound = $true
                }
    }

    if($isFound -eq $false)
    {
    #If the particular command we are looking for can't be found, create it to be imported.
                Write-Verbose "No line found for $Privilege - Adding new line for $DomainAccount"
                "$Privilege`=$DomainAccount" | Out-File ($TemporaryFolderPath+"\"+$ApplyFileName) -Append
            }

    #Import the new .inf into the local security policy.
            if ($pscmdlet.ShouldProcess($DomainAccount, "Account be added to Local Security with $Privilege privilege?"))
    {
    # yes, Run the import:
                Write-Verbose "Importing TemporaryFolderPath`\$ApplyFileName"
                $SeceditApplyResults = SECEDIT /configure /db secedit.sdb /cfg ($TemporaryFolderPath+"\"+$ApplyFileName)

    #Verify that update was successful (string reading, blegh.)
                if($SeceditApplyResults[$SeceditApplyResults.Count-2] -eq "The task has completed successfully.")
    {
    #Success, return true
                    Write-Verbose "Import was successful."
                    If($ReturnOutput){Write-Output $true}
                }
    else
                {
    #Import failed for some reason
                    Write-Verbose "Import from TemporaryFolderPath`\$ApplyFileName failed."
                    If($ReturnOutput){
                        Write-Output $false
                        Write-Error -Message "The import from $TemporaryFolderPath`\$ApplyFileName using secedit failed. Full Text Below:`n$SeceditApplyResults)"
                    }
                }
    }
    }
    else
        {
    #Export failed for some reason.
            Write-Verbose "Export to $TemporaryFolderPath\UserRightsAsTheyExist.inf failed."
            If($ReturnOutput){
                Write-Output $false
                Write-Error -Message "The export to $TemporaryFolderPath\UserRightsAsTheyExist.inf from secedit failed. Full Text Below:`n$SeceditResults)"
            }
        
    }

    Write-Verbose "Cleaning up temporary files that were created."
        #Delete the two temp files we created.
        Remove-TempFiles
    
}

Function Validate-Conditions{

    [CmdletBinding(DefaultParametersetName="OS")]
    param(   

    [parameter(Mandatory=$true)]
    [ValidateSet('VersionGreaterThanOrEqualTo','VersionGreaterThan','VersionLessThanOrEqualTo','VersionLessThan','VersionNotEqualTo','VersionEqualTo','ValueEqualTo','ValueNotEqualTo')]
    $CompareType, 
    
    [parameter(Mandatory=$false)]
    [switch] $Reverse, 

    [parameter(Mandatory=$false,ParameterSetName="OS")]
    [string] $OSVersion, 

    [parameter(Mandatory=$false,ParameterSetName="Reg")]
    [string] $RegKey,

    [parameter(Mandatory=$false,ParameterSetName="Reg")]
    [string] $RegValue,

    [parameter(Mandatory=$true,ParameterSetName="File","Hash")]
    [string] $FilePath, 
    
    [parameter(Mandatory=$false,ParameterSetName="File")]
    [string] $FileSpecialFolder,

    [parameter(Mandatory=$false,ParameterSetName="File")]
    [version] $FileVersion,

    [parameter(Mandatory=$false,ParameterSetName="Hash")]
    [string] $HashValue

    )
    Begin{
        ## Get the name of this function
        [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

        if (-not $PSBoundParameters.ContainsKey('Verbose')) {
            $VerbosePreference = $PSCmdlet.SessionState.PSVariable.GetValue('VerbosePreference')
        }

        #set to true, but process value to prove its false
        #If reverse, set default value to false then try to prove its true
        If($Reverse){$Results = $False}Else{$Results = $True}

    }
    Process{
        
        switch ($PsCmdlet.ParameterSetName){
            "OS"  { 
                    # Validate OS check
                    #---------------------    
                    If ($OSVersion -eq $null -or $OSVersion -eq ""){
                        Write-LogEntry -Message ("No Operating System condition found, ignoring OS conditions") -Source ${CmdletName} 
                    }
                    Else{
                        [psobject]$envOS = Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue'
                        [string]$envOSName = $envOS.Caption.Trim()
                        [string]$envOSServicePack = $envOS.CSDVersion
                        [version]$envOSVersion = $envOS.Version
                        $CurrentValue = $envOSVersion
                    }

                    $ValidateValue = $OSVersion
            }

            "Reg" { If ($RegKey -eq $null -or $RegKey -eq ""){
                        Write-LogEntry -Message ("No registry condition found, continuing install") -Source ${CmdletName}
                    }
                    Else{
                        #Check XML for Registry conditions
                        $RegKey = $RegKey.Replace("\","/")
                        $KeyPath = $RegKey -split '/'
                        $KeyPath = $KeyPath[0..($KeyPath.count-2)] -join '/'
                        $KeyPath = $KeyPath.Replace("/","\")
                        $KeyName = Split-Path -Path $RegKey -Leaf
                        $CurrentValue = Get-RegistryKey -Key "$KeyPath" -Value $KeyName
                    }

                    $ValidateValue = $RegValue
            }

            "File" {
                    # Validate File check
                    #-------------------------
                    If (!(Test-Path $FilePath)){
                        Write-LogEntry -Message ("File: " + $FilePath + " not found!") -Source ${CmdletName}
                    }
                    Else{
                        #get file info 
                        $FileValue = Get-item $FilePath
                        If($FileVersion){
                            $CurrentValue = $FileValue.VersionInfo | Select -ExpandProperty ProductVersion
                        }
                    }

                    $ValidateValue = $FileVersion
            }

            "Hash" {
                    # Validate File check
                    #-------------------------
                    If (!(Test-Path -Path $FilePath)){
                        Write-LogEntry -Message ("File: " + $FilePath + " not found!") -Source ${CmdletName}
                    }
                    Else{
                        #get file info
                        $Hashes = @()
                        $Hashes += Get-FileHash -Path $FilePath -Algorithm MD5 | Select -ExpandProperty Hash
                        $Hashes += Get-FileHash -Path $FilePath -Algorithm SHA1 | Select -ExpandProperty Hash
                        $Hashes += Get-FileHash -Path $FilePath -Algorithm SHA256 | Select -ExpandProperty Hash
                        $Hashes += Get-FileHash -Path $FilePath -Algorithm SHA384 | Select -ExpandProperty Hash
                        $Hashes += Get-FileHash -Path $FilePath -Algorithm SHA512 | Select -ExpandProperty Hash
                        
                        If($Hashes){
                            #overwrite any comparetype argument
                            $CompareType = "MatchesEqualTo"
                            $CurrentValue = $Hashes
                        }
                    }

                    $ValidateValue = $HashValue

                   }

        } #end switch SetName

        #compare Currentversion with Validate version
        If($CurrentValue -and $ValidateValue){
            switch($CompareType){
                "VersionEqualTo"              {
                    If ($CurrentValue -eq $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is EQUAL TO given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    } 
                }
                "VersionGreaterThanOrEqualTo" {
                    If ($CurrentValue -ge $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is GREATER THAN OR EQUAL TO given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    }
                }

                "VersionGreaterThan"          {
                    If ($CurrentValue -gt $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is GREATER THAN given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    }
                }

                "VersionNotEqualTo"           {
                    If ($CurrentValue -ne $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is NOT EQUAL TO given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    }
                }

                "VersionLessThanOrEqualTo"     {
                    If ($CurrentValue -le $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is LESS THAN OR EQUAL TO given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    }
                }

                "VersionLessThan"              {
                    If ($CurrentValue -lt $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is LESS THAN given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    }
                }
                            
                "ValueEqualTo"              {
                    If ($CurrentValue -eq $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is EQUAL TO given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    } 
                }

                "ValueNotEqualTo"              {
                    If ($CurrentValue -ne $ValidateValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$CurrentValue] is EQUAL TO given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    } 
                }

                #used soley for hash values
                "MatchesEqualTo"                {
                    $MatchValue = $CurrentValue -match $ValidateValue
                    If ($MatchValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "[$MatchValue] MATCHES a given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    }
                }

                #used soley for hash values
                "MatchesNotEqualTo"                {
                    $MatchValue = $CurrentValue -match $ValidateValue
                    If (!$MatchValue){
                        If($VerbosePreference -eq "Continue"){Write-LogEntry -Message "Current value or values do NOT MATCH a given value [$ValidateValue]" -Source ${CmdletName} -Severity 4}
                        If($Reverse){$Results = $True}Else{$Results = $false}
                    }
                }
            } #end switch OSCompare
        }


    }
    End{
        return $Results
    }
  
}

Function Convert-ArgumentEnv{
    param(
    [parameter(Mandatory=$false)]
    [Alias('Argument')]
    [string] $FullArgument,

    [parameter(Mandatory=$false)]
    [string] $AddVar,

    [parameter(Mandatory=$false)]
    [string] $AddEnv
    )
    
    $Vars = $FullArgument -split '%'
    $NewArgument=@()
    Foreach ($Var in $Vars){
        Switch ($Var) {
            {$_ -ilike '*PROGRAMFILES(X86)*'}{$Var = $Var -ireplace [regex]::Escape('PROGRAMFILES(X86)'),${env:ProgramFilesX86}}
            {$_ -ilike '*PROGRAMFILES*'}{$Var = $Var -ireplace 'PROGRAMFILES',"$env:ProgramFiles"}
            {$_ -ilike '*ALLUSERSPROFILE*'}{$Var = $Var -ireplace 'ALLUSERSPROFILE',"$env:AllUsersProfile"}
            {$_ -ilike '*LOCALAPPDATA*'}{$Var = $Var -ireplace 'LOCALAPPDATA',"$env:LocalAppData"}
            {$_ -ilike '*APPDATA*' -and $_ -inotlike '*LOCALAPPDATA*'}{$Var = $Var -ireplace 'APPDATA',"$env:AppData"}
            {$_ -ilike '*PUBLIC*'}{$Var = $Var -ireplace 'PUBLIC',"$env:Public"}
            {$_ -ilike '*WINDIR*'}{$Var = $Var -ireplace 'WINDIR',"$env:WinDir"}
            {$_ -ilike '*TEMP*' -and $Var -inotlike '*TEMP\*'}{$Var = $Var -ireplace 'TEMP',"$env:Temp"}
            
        }
        If($AddVar -and $AddEnv){
            $Var = $Var -ireplace "$AddVar","$AddEnv"
        }
        $NewArgument += $Var
        
    }
    Return $NewArgument -join ''

}


#region Function Get-InstalledApplication
Function Get-InstalledApplication {
    <#
    .SYNOPSIS
        Retrieves information about installed applications.
    .DESCRIPTION
        Retrieves information about installed applications by querying the registry. You can specify an application name, a product code, or both.
        Returns information about application publisher, name & version, product code, uninstall string, install source, location, date, and application architecture.
    .PARAMETER Name
        The name of the application to retrieve information for. Performs a contains match on the application display name by default.
    .PARAMETER Exact
        Specifies that the named application must be matched using the exact name.
    .PARAMETER WildCard
        Specifies that the named application must be matched using a wildcard search.
    .PARAMETER RegEx
        Specifies that the named application must be matched using a regular expression search.
    .PARAMETER ProductCode
        The product code of the application to retrieve information for.
    .PARAMETER IncludeUpdatesAndHotfixes
        Include matches against updates and hotfixes in results.
    .EXAMPLE
        Get-InstalledApplication -Name 'Adobe Flash'
    .EXAMPLE
        Get-InstalledApplication -ProductCode '{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
    .NOTES
    .LINK
        http://psappdeploytoolkit.com
    #>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string[]]$Name,
		[Parameter(Mandatory=$false)]
		[switch]$Exact = $false,
		[Parameter(Mandatory=$false)]
		[switch]$WildCard = $false,
		[Parameter(Mandatory=$false)]
		[switch]$RegEx = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$ProductCode,
		[Parameter(Mandatory=$false)]
		[switch]$IncludeUpdatesAndHotfixes
	)
	
	Begin {
		 ## Get the name of this function
         [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name

         #  Registry keys for native and WOW64 applications
        [string[]]$regKeyApplications = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
	}
	Process {
		If ($name) {
			Write-LogEntry -Message "Get information for installed Application Name(s) [$($name -join ', ')].." -Severity 4 -Source ${CmdletName} -Outhost:$Global:Verbose
		}
		If ($productCode) {
			Write-LogEntry -Message "Get information for installed Product Code [$ProductCode].." -Severity 4 -Source ${CmdletName} -Outhost:$Global:Verbose
		}
		
		## Enumerate the installed applications from the registry for applications that have the "DisplayName" property
		[psobject[]]$regKeyApplication = @()
		ForEach ($regKey in $regKeyApplications) {
			If (Test-Path -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath') {
				[psobject[]]$UninstallKeyApps = Get-ChildItem -LiteralPath $regKey -ErrorAction 'SilentlyContinue' -ErrorVariable '+ErrorUninstallKeyPath'
				ForEach ($UninstallKeyApp in $UninstallKeyApps) {
					Try {
						[psobject]$regKeyApplicationProps = Get-ItemProperty -LiteralPath $UninstallKeyApp.PSPath -ErrorAction 'Stop'
						If ($regKeyApplicationProps.DisplayName) { [psobject[]]$regKeyApplication += $regKeyApplicationProps }
					}
					Catch{
						Write-LogEntry -Message "Unable to enumerate properties from registry key path [$($UninstallKeyApp.PSPath)]." -Severity 2 -Source ${CmdletName} -Outhost:$Global:OutTohost
						Continue
					}
				}
			}
		}
		If ($ErrorUninstallKeyPath) {
			Write-LogEntry -Message "The following error(s) took place while enumerating installed applications from the registry." -Severity 2 -Source ${CmdletName} -Outhost:$Global:OutTohost
		}
		
		## Create a custom object with the desired properties for the installed applications and sanitize property details
		[psobject[]]$installedApplication = @()
		ForEach ($regKeyApp in $regKeyApplication) {
			Try {
				[string]$appDisplayName = ''
				[string]$appDisplayVersion = ''
				[string]$appPublisher = ''
				
				## Bypass any updates or hotfixes
				If (-not $IncludeUpdatesAndHotfixes) {
					If ($regKeyApp.DisplayName -match '(?i)kb\d+') { Continue }
					If ($regKeyApp.DisplayName -match 'Cumulative Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Security Update') { Continue }
					If ($regKeyApp.DisplayName -match 'Hotfix') { Continue }
				}
				
				## Remove any control characters which may interfere with logging and creating file path names from these variables
				$appDisplayName = $regKeyApp.DisplayName -replace '[^\u001F-\u007F]',''
				$appDisplayVersion = $regKeyApp.DisplayVersion -replace '[^\u001F-\u007F]',''
				$appPublisher = $regKeyApp.Publisher -replace '[^\u001F-\u007F]',''
				
				## Determine if application is a 64-bit application
				[boolean]$Is64BitApp = If (($is64Bit) -and ($regKeyApp.PSPath -notmatch '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node')) { $true } Else { $false }
				
				If ($ProductCode) {
					## Verify if there is a match with the product code passed to the script
					If ($regKeyApp.PSChildName -match [regex]::Escape($productCode)) {
						Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] matching product code [$productCode]" -Source ${CmdletName} -Outhost
						$installedApplication += New-Object -TypeName 'PSObject' -Property @{
							UninstallSubkey = $regKeyApp.PSChildName
							ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
							DisplayName = $appDisplayName
							DisplayVersion = $appDisplayVersion
							UninstallString = $regKeyApp.UninstallString
							InstallSource = $regKeyApp.InstallSource
							InstallLocation = $regKeyApp.InstallLocation
							InstallDate = $regKeyApp.InstallDate
							Publisher = $appPublisher
							Is64BitApplication = $Is64BitApp
						}
					}
				}
				
				If ($name) {
					## Verify if there is a match with the application name(s) passed to the script
					ForEach ($application in $Name) {
						$applicationMatched = $false
						If ($exact) {
							#  Check for an exact application name match
							If ($regKeyApp.DisplayName -eq $application) {
								$applicationMatched = $true
								Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using exact name matching for search term [$application]" -Source ${CmdletName} -Outhost
							}
						}
						ElseIf ($WildCard) {
							#  Check for wildcard application name match
							If ($regKeyApp.DisplayName -like $application) {
								$applicationMatched = $true
								Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using wildcard matching for search term [$application]" -Source ${CmdletName} -Outhost
							}
						}
						ElseIf ($RegEx) {
							#  Check for a regex application name match
							If ($regKeyApp.DisplayName -match $application) {
								$applicationMatched = $true
								Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using regex matching for search term [$application]" -Source ${CmdletName} -Outhost
							}
						}
						#  Check for a contains application name match
						ElseIf ($regKeyApp.DisplayName -match [regex]::Escape($application)) {
							$applicationMatched = $true
							Write-LogEntry -Message "Found installed application [$appDisplayName] version [$appDisplayVersion] using contains matching for search term [$application]" -Source ${CmdletName} -Outhost
						}
						
						If ($applicationMatched) {
							$installedApplication += New-Object -TypeName 'PSObject' -Property @{
								UninstallSubkey = $regKeyApp.PSChildName
								ProductCode = If ($regKeyApp.PSChildName -match $MSIProductCodeRegExPattern) { $regKeyApp.PSChildName } Else { [string]::Empty }
								DisplayName = $appDisplayName
								DisplayVersion = $appDisplayVersion
								UninstallString = $regKeyApp.UninstallString
								InstallSource = $regKeyApp.InstallSource
								InstallLocation = $regKeyApp.InstallLocation
								InstallDate = $regKeyApp.InstallDate
								Publisher = $appPublisher
								Is64BitApplication = $Is64BitApp
							}
						}
					}
				}
			}
			Catch {
				Write-LogEntry -Message "Failed to resolve application details from registry for [$appDisplayName]." -Severity 3 -Source ${CmdletName} -Outhost
				Continue
			}
		}
		
		Write-Output -InputObject $installedApplication
	}
	End {
	}
}
#endregion

#region Function Test-MSUpdates
Function Test-MSUpdates {
<#
.SYNOPSIS
	Test whether a Microsoft Windows update is installed.
.DESCRIPTION
	Test whether a Microsoft Windows update is installed.
.PARAMETER KBNumber
	KBNumber of the update.
.PARAMETER ContinueOnError
	Suppress writing log message to console on failure to write message to log file. Default is: $true.
.EXAMPLE
	Test-MSUpdates -KBNumber 'KB2549864'
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true,Position=0,HelpMessage='Enter the KB Number for the Microsoft Update')]
		[ValidateNotNullorEmpty()]
		[string]$KBNumber,
		[Parameter(Mandatory=$false,Position=1)]
		[ValidateNotNullorEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	}
	Process {
		Try {
			Write-LogEntry -Message "Check if Microsoft Update [$kbNumber] is installed." -Source ${CmdletName}
			
			## Default is not found
			[boolean]$kbFound = $false
			
			## Check for update using built in PS cmdlet which uses WMI in the background to gather details
			If ([int]$envPSVersionMajor -ge 3) {
				Get-Hotfix -Id $kbNumber -ErrorAction 'SilentlyContinue' | ForEach-Object { $kbFound = $true }
			}
			Else {
				Write-LogEntry -Message 'Older version of Powershell detected, Get-Hotfix cmdlet is not supported.' -Source ${CmdletName}
			}
						
			If (-not $kbFound) {
				Write-LogEntry -Message 'Unable to detect Windows update history via Get-Hotfix cmdlet. Trying via COM object.' -Source ${CmdletName}
			
				## Check for update using ComObject method (to catch Office updates)
				[__comobject]$UpdateSession = New-Object -ComObject "Microsoft.Update.Session"
				[__comobject]$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
				#  Indicates whether the search results include updates that are superseded by other updates in the search results
				$UpdateSearcher.IncludePotentiallySupersededUpdates = $false
				#  Indicates whether the UpdateSearcher goes online to search for updates.
				$UpdateSearcher.Online = $false
				[int32]$UpdateHistoryCount = $UpdateSearcher.GetTotalHistoryCount()
				If ($UpdateHistoryCount -gt 0) {
					[psobject]$UpdateHistory = $UpdateSearcher.QueryHistory(0, $UpdateHistoryCount) |
									Select-Object -Property 'Title','Date',
															@{Name = 'Operation'; Expression = { Switch ($_.Operation) { 1 {'Installation'}; 2 {'Uninstallation'}; 3 {'Other'} } } },
															@{Name = 'Status'; Expression = { Switch ($_.ResultCode) { 0 {'Not Started'}; 1 {'In Progress'}; 2 {'Successful'}; 3 {'Incomplete'}; 4 {'Failed'}; 5 {'Aborted'} } } },
															'Description' |
									Sort-Object -Property 'Date' -Descending
					ForEach ($Update in $UpdateHistory) {
						If (($Update.Operation -ne 'Other') -and ($Update.Title -match "\($KBNumber\)")) {
							$LatestUpdateHistory = $Update
							Break
						}
					}
					If (($LatestUpdateHistory.Operation -eq 'Installation') -and ($LatestUpdateHistory.Status -eq 'Successful')) {
						Write-LogEntry -Message "Discovered the following Microsoft Update: `n$($LatestUpdateHistory | Format-List | Out-String)" -Source ${CmdletName}
						$kbFound = $true
					}
					$null = [Runtime.Interopservices.Marshal]::ReleaseComObject($UpdateSession)
					$null = [Runtime.Interopservices.Marshal]::ReleaseComObject($UpdateSearcher)
				}
				Else {
					Write-LogEntry -Message 'Unable to detect Windows update history via COM object.' -Source ${CmdletName}
				}
			}
			
			## Return Result
			If (-not $kbFound) {
				Write-LogEntry -Message "Microsoft Update [$kbNumber] is not installed." -Source ${CmdletName}
				Write-Output -InputObject $false
			}
			Else {
				Write-LogEntry -Message "Microsoft Update [$kbNumber] is installed." -Source ${CmdletName}
				Write-Output -InputObject $true
			}
		}
		Catch {
			Write-LogEntry -Message "Failed discovering Microsoft Update [$kbNumber]." -Severity 3 -Source ${CmdletName}
			If (-not $ContinueOnError) {
				Throw "Failed discovering Microsoft Update [$kbNumber]: $($_.Exception.Message)"
			}
		}
	}
	End {
	}
}
#endregion

#region Function Get-RegistryKey
Function Get-RegistryKey {
<#
.SYNOPSIS
	Retrieves value names and value data for a specified registry key or optionally, a specific value.
.DESCRIPTION
	Retrieves value names and value data for a specified registry key or optionally, a specific value.
	If the registry key does not exist or contain any values, the function will return $null by default. To test for existence of a registry key path, use built-in Test-Path cmdlet.
.PARAMETER Key
	Path of the registry key.
.PARAMETER Value
	Value to retrieve (optional).
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.PARAMETER ReturnEmptyKeyIfExists
	Return the registry key if it exists but it has no property/value pairs underneath it. Default is: $false.
.PARAMETER DoNotExpandEnvironmentNames
	Return unexpanded REG_EXPAND_SZ values. Default is: $false.	
.PARAMETER ContinueOnError
	Continue if an error is encountered. Default is: $true.
.EXAMPLE
	Get-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.EXAMPLE
	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\iexplore.exe'
.EXAMPLE
	Get-RegistryKey -Key 'HKLM:Software\Wow6432Node\Microsoft\Microsoft SQL Server Compact Edition\v3.5' -Value 'Version'
.EXAMPLE
	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Value 'Path' -DoNotExpandEnvironmentNames 
	Returns %ProgramFiles%\Java instead of C:\Program Files\Java
.EXAMPLE
	Get-RegistryKey -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Example' -Value '(Default)'
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Key,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$SID,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[switch]$ReturnEmptyKeyIfExists = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[switch]$DoNotExpandEnvironmentNames = $false,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullOrEmpty()]
		[boolean]$ContinueOnError = $true
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		
	}
	Process {
		Try {
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID
			If ($PSBoundParameters.ContainsKey('SID')) {
				[string]$key = Convert-RegistryPath -Key $key -SID $SID
			}
			Else {
				[string]$key = Convert-RegistryPath -Key $key
			}
			
			## Check if the registry key exists
			If (-not (Test-Path -LiteralPath $key -ErrorAction 'Stop')) {
				Write-LogEntry  -Message "Registry key [$key] does not exist. Return `$null." -Severity 2 -Source ${CmdletName}
				$regKeyValue = $null
			}
			Else {
				If ($PSBoundParameters.ContainsKey('Value')) {
					Write-LogEntry  -Message "Get registry key [$key] value [$value]." -Source ${CmdletName}
				}
				Else {
					Write-LogEntry  -Message "Get registry key [$key] and all property values." -Source ${CmdletName}
				}
				
				## Get all property values for registry key
				$regKeyValue = Get-ItemProperty -LiteralPath $key -ErrorAction 'Stop'
				[int32]$regKeyValuePropertyCount = $regKeyValue | Measure-Object | Select-Object -ExpandProperty 'Count'
				
				## Select requested property
				If ($PSBoundParameters.ContainsKey('Value')) {
					#  Check if registry value exists
					[boolean]$IsRegistryValueExists = $false
					If ($regKeyValuePropertyCount -gt 0) {
						Try {
							[string[]]$PathProperties = Get-Item -LiteralPath $Key -ErrorAction 'Stop' | Select-Object -ExpandProperty 'Property' -ErrorAction 'Stop'
							If ($PathProperties -contains $Value) { $IsRegistryValueExists = $true }
						}
						Catch { }
					}
					
					#  Get the Value (do not make a strongly typed variable because it depends entirely on what kind of value is being read)
					If ($IsRegistryValueExists) {
						If ($DoNotExpandEnvironmentNames) { #Only useful on 'ExpandString' values
							If ($Value -like '(Default)') {
								$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($null,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
							}
							Else {
								$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($Value,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)	
							}							
						}
						ElseIf ($Value -like '(Default)') {
							$regKeyValue = $(Get-Item -LiteralPath $key -ErrorAction 'Stop').GetValue($null)
						}
						Else {
							$regKeyValue = $regKeyValue | Select-Object -ExpandProperty $Value -ErrorAction 'SilentlyContinue'
						}
					}
					Else {
						Write-LogEntry  -Message "Registry key value [$Key] [$Value] does not exist. Return `$null." -Source ${CmdletName}
						$regKeyValue = $null
					}
				}
				## Select all properties or return empty key object
				Else {
					If ($regKeyValuePropertyCount -eq 0) {
						If ($ReturnEmptyKeyIfExists) {
							Write-LogEntry  -Message "No property values found for registry key. Return empty registry key object [$key]." -Source ${CmdletName}
							$regKeyValue = Get-Item -LiteralPath $key -Force -ErrorAction 'Stop'
						}
						Else {
							Write-LogEntry  -Message "No property values found for registry key. Return `$null." -Source ${CmdletName}
							$regKeyValue = $null
						}
					}
				}
			}
			Write-Output -InputObject ($regKeyValue)
		}
		Catch {
			If (-not $Value) {
				Write-LogEntry  -Message "Failed to read registry key [$key]." -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to read registry key [$key]: $($_.Exception.Message)"
				}
			}
			Else {
				Write-LogEntry  -Message "Failed to read registry key [$key] value [$value]." -Severity 3 -Source ${CmdletName}
				If (-not $ContinueOnError) {
					Throw "Failed to read registry key [$key] value [$value]: $($_.Exception.Message)"
				}
			}
		}
	}
	End {
		
	}
}
#endregion


#region Function Convert-RegistryPath
Function Convert-RegistryPath {
<#
.SYNOPSIS
	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
.DESCRIPTION
	Converts the specified registry key path to a format that is compatible with built-in PowerShell cmdlets.
	Converts registry key hives to their full paths. Example: HKLM is converted to "Registry::HKEY_LOCAL_MACHINE".
.PARAMETER Key
	Path to the registry key to convert (can be a registry hive or fully qualified path)
.PARAMETER SID
	The security identifier (SID) for a user. Specifying this parameter will convert a HKEY_CURRENT_USER registry key to the HKEY_USERS\$SID format.
	Specify this parameter from the Invoke-HKCURegistrySettingsForAllUsers function to read/edit HKCU registry settings for all users on the system.
.EXAMPLE
	Convert-RegistryPath -Key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.EXAMPLE
	Convert-RegistryPath -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{1AD147D0-BE0E-3D6C-AC11-64F6DC4163F1}'
.NOTES
.LINK
	http://psappdeploytoolkit.com
#>
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullorEmpty()]
		[string]$Key,
		[Parameter(Mandatory=$false)]
		[ValidateNotNullorEmpty()]
		[string]$SID
	)
	
	Begin {
		## Get the name of this function and write header
		[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
		
	}
	Process {
		## Convert the registry key hive to the full path, only match if at the beginning of the line
		If ($Key -match '^HKLM:\\|^HKCU:\\|^HKCR:\\|^HKU:\\|^HKCC:\\|^HKPD:\\') {
			#  Converts registry paths that start with, e.g.: HKLM:\
			$key = $key -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
			$key = $key -replace '^HKCR:\\', 'HKEY_CLASSES_ROOT\'
			$key = $key -replace '^HKCU:\\', 'HKEY_CURRENT_USER\'
			$key = $key -replace '^HKU:\\', 'HKEY_USERS\'
			$key = $key -replace '^HKCC:\\', 'HKEY_CURRENT_CONFIG\'
			$key = $key -replace '^HKPD:\\', 'HKEY_PERFORMANCE_DATA\'
		}
		ElseIf ($Key -match '^HKLM:|^HKCU:|^HKCR:|^HKU:|^HKCC:|^HKPD:') {
			#  Converts registry paths that start with, e.g.: HKLM:
			$key = $key -replace '^HKLM:', 'HKEY_LOCAL_MACHINE\'
			$key = $key -replace '^HKCR:', 'HKEY_CLASSES_ROOT\'
			$key = $key -replace '^HKCU:', 'HKEY_CURRENT_USER\'
			$key = $key -replace '^HKU:', 'HKEY_USERS\'
			$key = $key -replace '^HKCC:', 'HKEY_CURRENT_CONFIG\'
			$key = $key -replace '^HKPD:', 'HKEY_PERFORMANCE_DATA\'
		}
		ElseIf ($Key -match '^HKLM\\|^HKCU\\|^HKCR\\|^HKU\\|^HKCC\\|^HKPD\\') {
			#  Converts registry paths that start with, e.g.: HKLM\
			$key = $key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
			$key = $key -replace '^HKCR\\', 'HKEY_CLASSES_ROOT\'
			$key = $key -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
			$key = $key -replace '^HKU\\', 'HKEY_USERS\'
			$key = $key -replace '^HKCC\\', 'HKEY_CURRENT_CONFIG\'
			$key = $key -replace '^HKPD\\', 'HKEY_PERFORMANCE_DATA\'
		}
		
		If ($PSBoundParameters.ContainsKey('SID')) {
			## If the SID variable is specified, then convert all HKEY_CURRENT_USER key's to HKEY_USERS\$SID				
			If ($key -match '^HKEY_CURRENT_USER\\') { $key = $key -replace '^HKEY_CURRENT_USER\\', "HKEY_USERS\$SID\" }
		}
		
		## Append the PowerShell drive to the registry key path
		If ($key -notmatch '^Registry::') {[string]$key = "Registry::$key" }
		
		If($Key -match '^Registry::HKEY_LOCAL_MACHINE|^Registry::HKEY_CLASSES_ROOT|^Registry::HKEY_CURRENT_USER|^Registry::HKEY_USERS|^Registry::HKEY_CURRENT_CONFIG|^Registry::HKEY_PERFORMANCE_DATA') {
			## Check for expected key string format
			Write-LogEntry  -Message "Return fully qualified registry key path [$key]." -Source ${CmdletName}
			Write-Output -InputObject $key
		}
		Else{
			#  If key string is not properly formatted, throw an error
			Throw "Unable to detect target registry hive in string [$key]."
		}
	}
	End {
		
	}
}
#endregion

##*===========================================================================
##* VARIABLES
##*===========================================================================
# Use function to get paths because Powershell ISE and other editors have differnt results
$scriptPath = Get-ScriptPath
[string]$scriptDirectory = Split-Path $scriptPath -Parent
[string]$scriptName = Split-Path $scriptPath -Leaf
[string]$scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($scriptName)

[string]$Version = "1.1.0"

#Create Paths
$Config = Get-ChildItem $scriptDirectory -Filter '*.config'
$SourceFiles = Join-Path $scriptDirectory -ChildPath "Source\$Version"

#check if running in verbose mode
$Global:Verbose = $true
If($PSBoundParameters.ContainsKey('Debug') -or $PSBoundParameters.ContainsKey('Verbose')){
    $Global:Verbose = $PsBoundParameters.Get_Item('Verbose')
    $VerbosePreference = 'Continue'
    Write-Verbose ("[{0}] [{1}] :: VERBOSE IS ENABLED" -f (Format-DatePrefix),$scriptName)
}
Else{
    $VerbosePreference = 'SilentlyContinue'
}

#build log name
[string]$FileName = $scriptBaseName +'.log'
#build global log fullpath
$Global:LogFilePath = Join-Path (Get-SMSTSENV -ReturnLogPath -NoWarning) -ChildPath $FileName


#grab all Show-ProgressStatus commands in script and count them
$script:Maxsteps = ([System.Management.Automation.PsParser]::Tokenize((Get-Content $scriptPath), [ref]$null) | Where-Object { $_.Type -eq 'Command' -and $_.Content -eq 'Show-ProgressStatus' }).Count
#set counter to one
$stepCounter = 1	

#not all files may match hash. This is for high security
#This could cause validation to faile and wont install package
$IgnoreHashCheck = $true

##*===========================================================================
##* MAIN
##*===========================================================================


#If config was found, continue
If($Config){
    $xmlConfigs = [xml](Get-Content -Path $Config.FullName)

    #grab package configs
    $packageConfigs = $xmlConfigs.configuration.packageConfigs.add

    #grab logpath
    $LogPath = $packageConfigs | Where {$_.Key -eq "LogPath"} | Select -ExpandProperty value
    $Global:LogFilePath = Convert-ArgumentEnv -FullArgument $LogPath
    #get the parent directory
    $LogPath = Split-Path $Global:LogFilePath -Parent
    New-Item -Path $LogPath -ItemType Directory -ErrorAction SilentlyContinue  | Out-null
    Write-Host "logging to file: $LogFilePath" -ForegroundColor Cyan

    $LegacyApplicationsPath = Join-Path $SourceFiles -ChildPath ($packageConfigs | Where {$_.Key -eq "LegacyApplicationsPath"} | Select -ExpandProperty value)
    $PrimaryPackagePath = Join-Path $SourceFiles -ChildPath ($packageConfigs | Where {$_.Key -eq "PrimaryPackagePath"} | Select -ExpandProperty value)
    $PostPackagePath = Join-Path $SourceFiles -ChildPath ($packageConfigs | Where {$_.Key -eq "PostPackagePath"} | Select -ExpandProperty value)
    $UpdatesPackagePath = Join-Path $SourceFiles -ChildPath ($packageConfigs | Where {$_.Key -eq "UpdatesPackagePath"} | Select -ExpandProperty value)
    
    #get the Accessory folder
    $AccessoryPackagePath = @()
    $AccessoryDirPath = Join-Path $SourceFiles -ChildPath ($packageConfigs | Where {$_.Key -eq "AccessoryDirectory"} | Select -ExpandProperty value)
    #, then build the paths to each product.xml
    (Get-ChildItem $AccessoryDirPath -Filter 'product.xml' -Recurse).FullName | %{[string[]]$AccessoryPackagePath += $_ }

}
Else{
   Write-LogEntry ("Missing configuration file under path [{0}], Unable to confinue" -f "$SourceFiles\$Version") -Severity 3 -Outhost
   Exit -1
}

### LEGACY CLEANUP/UNINSTALL
#-------------------------------------
Write-LogEntry "Checking if any legacy application are installed..." -Outhost
If (Test-Path $LegacyApplicationsPath)
{
	$xmlLegacy = [xml](Get-Content -Path $LegacyApplicationsPath)
    $xmlLegacyApps = $xmlLegacy.LegacyApps.UninstallMSIApps.MSIApp
    Foreach ($App in $xmlLegacyApps){
        $AppName = $App.Name
        $AppGuid = $App.Guid
                
        [psobject]$MsiExits = Get-InstalledApplication -ProductCode $AppGuid
        If ($MsiExits) {
            Write-LogEntry ("Uninstalling [{0}]..." -f $AppName) -Outhost
            Start-Process 'msiexec' -ArgumentList "/x $AppGuid /qn /norestart /l*v `"$LogPath\$AppName_uninstall.log`"" -NoNewWindow -PassThru -Wait
        }
        Else{
            Write-LogEntry ("[{0}] not found by GUID detection {1}" -f $AppName,$AppGuid) -Outhost
        }
    }
}


$OrderOfProductXMLs = @()
#build the order of install
[string[]]$OrderOfProductXMLs = $PrimaryPackagePath,$PostPackagePath,$UpdatesPackagePath + $AccessoryPackagePath
#test $OrderOfProductXMLs = $PrimaryPackagePath

$p = 0

#loop through each product.xml
Foreach($ProductXML in $OrderOfProductXMLs){
    
    $xml = [xml](get-content -Path $ProductXML)

    $WorkingFolder = Split-Path $ProductXML -Parent

    #Used for uninstall section only
    $xmlUinstall = $xml.Package.UninstallString
        
    #default exit codes
    $ExitValues = "1,2"

    $PrereqCommands = $xml.Package.Commands.PrereqCommand
    $PrimaryCommands = $xml.Package.Commands.PrimaryCommand

    #merge both prereqs and primary commands together
    #placinf prereqs first
    $MergeCommands = $xml.Package.Commands.PrereqCommand + $xml.Package.Commands.PrimaryCommand
    
    #start the number of commands
    $CommandInc = 1 
    $CommandCount = $MergeCommands.Count
    If(!$CommandCount){$CommandCount = 1}

    Foreach ($Command in $MergeCommands)
    {
        #Test-->Foreach ($Command in $MergeCommands){If($Command.PackageFile -eq "Setup.exe"){break}}
        $AppName = $Command.Name
        $LogPreName = $AppName.replace(" ","").Trim()
        
        $ValidCondition = $true
        #Get directory full path to file
        #--------------------------------
        $PackagePath = Join-Path $WorkingFolder -ChildPath $Command.PackageFile
        If(Test-Path $PackagePath){
            [IO.FileInfo[]]$Package = Get-ChildItem $PackagePath
            Write-LogEntry ("Application exists in path [{0}]" -f $Package.FullName) -Severity 1 -Outhost
        }
        Else{
            Write-LogEntry ("Application does not exist in path [{0}], Unable to install" -f $PackagePath) -Severity 2 -Outhost
            $ValidCondition = $false
        }

        #check OS Conditions
        $OSConditions = @{}
        Foreach($condition in $Command.InstallConditions.OSVersionCheck){
            If($condition.CompareType){$OSConditions.Add('CompareType',$condition.CompareType)}
            If($condition.Value){$OSConditions.Add('OSVersion',$condition.Value)}

            #if continue is still true, keep comparing until false
            If($ValidCondition){
                $ValidCondition = Validate-Conditions @OSConditions -Verbose:$Global:Verbose
            }
            #reset OS condition to null
            $OSConditions = @{}
        }
        
        #check Registry Conditions
        $REGConditions = @{}
        Foreach($condition in $Command.InstallConditions.RegistryCheck){
            If($condition.CompareType){$REGConditions.Add('CompareType',$condition.CompareType)}
            If($condition.Key){$REGConditions.Add('RegKey',$condition.Key)}
            If($condition.Value){$REGConditions.Add('RegValue',$condition.Value)}
            
            #if continue is still true, keep comparing until false
            If($ValidCondition){
                $ValidCondition = Validate-Conditions @REGConditions -Verbose:$Global:Verbose
            }

            #reset OS condition to null
            $REGConditions = @{}
        }

        #check File Conditions
        $FileConditions = @{}
        Foreach($condition in $Command.InstallConditions.FileCheck){
            If($condition.CompareType){$FileConditions.Add('CompareType',$condition.CompareType)}
            If($condition.SpecialFolder){$FileConditions.Add('FileSpecialFolder',$condition.SpecialFolder)}
            If($condition.PackageFile){$FileConditions.Add('FilePath',$PackagePath)}
            If($condition.Version){$FileConditions.Add('FileVersion',$condition.Version)}
            
            If($condition.SpecialFolder){
                $FileConditions.Add('FileSpecialFolder',$condition.SpecialFolder)

                switch($condition.SpecialFolder){
                    'System'           {$PackagePath = Join-Path "$env:SystemRoot\system32" -ChildPath $PackagePath}
                    'ProgramFiles'     {$PackagePath = Join-Path $env:ProgramFiles -ChildPath $PackagePath}
                    'ProgramFilesx86'  {$PackagePath = Join-Path ${env:ProgramFilesX86} -ChildPath $PackagePath}
                    'SystemRoot'       {$PackagePath = Join-Path $env:SystemRoot -ChildPath $PackagePath}
                    'AllUsers'         {$PackagePath = Join-Path $env:ALLUSERSPROFILE -ChildPath $PackagePath}
                    'Temp'             {$PackagePath = Join-Path $env:TEMP -ChildPath $PackagePath}
                }
            }
            
            #if continue is still true, keep comparing until false
            If($ValidCondition){
                $ValidCondition = Validate-Conditions @FileConditions -Verbose:$Global:Verbose
            }

            #reset condition object to null, for the next loop
            $FileConditions = @{}
        }

        #check hash conditions
        If(!$IgnoreHashCheck -and $Command.FileHash){
            $ValidCondition = Validate-Conditions -CompareType ValueEqualTo -FilePath $PackagePath -HashValue $Command.FileHash -Verbose:$Global:Verbose -Reverse
        }

        #IF all conditions are valideated, then continue the install, otherwise skip command
        If ($ValidCondition -eq $true){
            
            $fileName = $Package.Name

            $PackageRoot = Split-Path $Package.FullName -Parent
            #build UI status for size detection
            # Larger than 200MB
            #-----------------------------------
            $InstallSize = $Command.EstimatedInstalledBytes
            If ($InstallSize -gt "204800000") { $Extras = ". This may take a while..."}
            Else{$Extras = "..."}

            #check if the xml has a name associated with PrimaryCommand, display status appropiately
            #---------------------------------------------------------------------------------------
            Show-ProgressStatus -Message ("Processing ({2} of {3}) :: Installing {0} [{1}]" -f $AppName,$fileName,$CommandInc,$CommandCount) -Step $p -MaxStep $CommandCount -Outhost
            If ($Command.Action){Write-LogEntry ("Running Action (" + $CommandInc + " of " + $CommandCount + ") :: " + $Command.Action + $Extras) -Outhost}
            Else{Write-LogEntry ("Running Command (" + $CommandInc + " of " + $CommandCount + ") :: " + $fileName + $Extras) -Outhost }
                
            #Get any identified successful exit codes for installation (EXE only)
            #--------------------------------------------------------------------
            $ExitCodes = $Command.ExitCodes.ExitCode
            If ($ExitCodes.Result -eq "Success"){
                $ExitValues = ($ExitCodes.Value|group|Select -ExpandProperty  Name) -join "|"
                Write-LogEntry -Message "Installation will ignore these exit codes: $ExitValues" -Outhost 
            }
                        
            #replace environment variables arguments with powershell env
            $Arguments = Convert-ArgumentEnv -FullArgument ($Command.Arguments)

            #remove any proceeding back slashes (used as escape char)
            #$Arguments = $Arguments -replace [Regex]::Escape('\"'),'"'

            #detect extension and build proper installer
            switch($Package.Extension){
                '.msu' {
                        $actionlabel = "update patch"
                        $Params = @{FilePath = "$env:windir\System32\wusa.exe"}

                        #if arguments exist, add them dynamically
                        If($Arguments){
                            $Params.Add('ArgumentList',"`"$($Package.FullName)`" $Arguments")
                        }
                        Else{
                            $Params.Add('ArgumentList',"`"$($Package.FullName)`" /quiet /norestart")
                        }
                
                        #check if KB already exists
                        $kbPattern = '(?i)kb\d{6,8}'
                        [string]$kbNumber = [regex]::Match($Package.Name, $kbPattern).ToString()
				        If (-not $kbNumber) { Continue }
                        If (Test-MSUpdates -KBNumber $kbNumber) {
                            Return
                        }
                }

                '.msp'  {
                        $actionlabel = "update patch"
                        $Params = @{FilePath = "$env:windir\System32\msiexec.exe"}

                        [psobject]$AppInstalled = Get-InstalledApplication $AppName
                        If ($AppInstalled) {
                            #if arguments exist, add them dynamically
                            If($Arguments){
                                #check if no restart exist; if so remove it
                                $Arguments = $Arguments -replace "/norestart",""
                                #change passive to quiet
                                $Arguments = $Arguments -replace "/passive","/quiet"
                                #apply arguments and /norestart again
                    
                                $Params.Add('ArgumentList',"/p `"$($Package.FullName)`" $Arguments /qn /norestart /l*v `"$LogPath\$LogPreName_install.log`"")
                            }
                            Else{
                                $Params.Add('ArgumentList',"/p `"$($Package.FullName)`" /norestart /l*v `"$LogPath\$LogPreName_install.log`"")
                            }
                        }
                        Else{
                            Return
                        }
                        
                }

                '.msi'  {
                        $actionlabel = "install application"
                        [psobject]$AppInstalled = Get-InstalledApplication $AppName
                        If ($AppInstalled) {
                            $InstallParam = "/fa"
                        }Else{
                            $InstallParam = "/i"
                        }
                        $Params = @{FilePath = "$env:windir\System32\msiexec.exe"}

                        #if arguments exist, add them dynamically
                        If($Arguments){
                            #check if no restart exist; if so remove it
                            $Arguments = $Arguments -replace "/norestart",""
                            #change passive to quiet
                            $Arguments = $Arguments -replace "/passive","/quiet"
                            #apply arguments and /norestart again
                    
                            $Params.Add('ArgumentList',"$InstallParam `"$($Package.FullName)`" $Arguments /qn /norestart /l*v `"$LogPath\$LogPreName_install.log`"")
                        }
                        Else{
                            $Params.Add('ArgumentList',"$InstallParam `"$($Package.FullName)`" /norestart /l*v `"$LogPath\$LogPreName_install.log`"")
                        }

                }

                '.exe'  {
                        $actionlabel = "install application"
                        $Params = @{FilePath = $Package.FullName}

                        #if arguments exist, add them dynamically
                        If($Arguments){
                            $Arguments = $Arguments -replace "/norestart",""
                            If($Arguments -like "*SQL*"){
                                #SQL installer; make silent
                                $Arguments = $Arguments -replace "/qs","/q"
                                $Arguments = $Arguments -replace "/QuietSimple","/QUIET"
                            }
                    
                            #determine if IIS file is in argument
                            If ($Arguments -like "*ISSFile*"){
                                $ISSFile = $Command.ISSFile
                                If ($Command.PackageFile -contains "\"){
                                    $Package = $Command.Replace('\','/')
                                    $PackagePathSplit = $Package -split '/'
                                    $PackagePathJoin = $PackagePathSplit[0..($PackagePathSplit.count-2)] -join '/'
                                    $PackagePath = $PackagePathJoin.Replace('/','\') 
                                    $Arguments = $Arguments.Replace("[ISSFile]","$PackageRoot\$ISSFile")
                                }
                                Else {
                                    $Arguments = $Arguments.Replace("[ISSFile]","$WorkingFolder\$ISSFile")
                                }
                            }

                            $Params.Add('ArgumentList',$Arguments)
                        }

                }

                '.bat' {
                        $actionlabel = "run script"   
                        $Params = @{FilePath = "$env:ComSpec"}
                        #if arguments exist, add them dynamically
                        If($Arguments){
                            $Params.Add('ArgumentList',"/c $Arguments")
                        }
                        Else{
                            $Params.Add('ArgumentList',"/c")
                        }
                }

                '.vbs' {
                        $actionlabel = "run script"    
                        $Params = @{FilePath = "$env:windir\System32\cscript.exe"}
                        #if arguments exist, add them dynamically
                        If($Arguments){
                            $Params.Add('ArgumentList',"//nologo `"$($Package.FullName)`" $Arguments")
                        }
                        Else{
                            $Params.Add('ArgumentList',"//nologo `"$($Package.FullName)`"")
                        }
                }

                '.ps1' {
                        $actionlabel = "run script" 
                        $Params = @{FilePath = "$pshome\powershell.exe"}
                        #if arguments exist, add them dynamically
                        If($Arguments){
                            $Params.Add('ArgumentList',"-ExecutionPolicy Bypass -File `"$($Package.FullName)`" $Arguments")
                        }
                        Else{
                            $Params.Add('ArgumentList',"-ExecutionPolicy Bypass -File `"$($Package.FullName)`"")
                        }
                }

            } #end switch

            ##===================================
            #convert Param to string to output
            $ParamString = ($Params.GetEnumerator() | % {"$($_.Value)"}) -join " "
            If($Global:Verbose){Write-LogEntry -Message ("RUNNING COMMAND: {0}" -f $ParamString) -Severity 4 -Outhost}

            #DO ACTION
            $result = Start-Process @Params -NoNewWindow -PassThru -Wait


            If($result.ExitCode -notmatch $ExitValues){
                Write-LogEntry -Message ("Failed to {0} [{1}]. Exit Code {2}" -f $actionlabel,$Package.Name,$result.ExitCode) -Severity 3 -Outhost     
            }
                  
        }
        Else{
             Show-ProgressStatus -Message ("Processing ({1} of {2}) :: Skipping {0}. Package didn't pass validation" -f $AppName,$CommandInc,$CommandCount) -Step $p -MaxStep $CommandCount -Outhost
        }
        $CommandInc = $CommandInc + 1

    } #end loop

}