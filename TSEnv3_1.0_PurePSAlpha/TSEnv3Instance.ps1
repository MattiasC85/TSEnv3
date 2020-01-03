#using module .\TSEnv3Mod.psm1 
Import-module -Force $PSScriptRoot\TSEnv3ModRCFinal.psm1

###For Verbose output
#Import-Module -Force $PSScriptRoot\TSEnv3ModRC.psm1 -ArgumentList $true

function Enable-TSDuplicateToken {

[CmdletBinding()]
param()

#https://gallery.technet.microsoft.com/scriptcenter/Enable-TSDuplicateToken-6f485980
#Copies the token of Lsass (System) to the current process (or thread really)

#Gives you access to the TSenv filemapping when running the script as an administrator.
 
#Thanks Truesec!

$signature = @"
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
     public struct TokPriv1Luid
     {
         public int Count;
         public long Luid;
         public int Attr;
     }

    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
    public const int TOKEN_QUERY = 0x00000008;
    public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;

    public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const UInt32 TOKEN_DUPLICATE = 0x0002;
    public const UInt32 TOKEN_IMPERSONATE = 0x0004;
    public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
      TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
      TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
      TOKEN_ADJUST_SESSIONID);

    public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege";
    public const int ANYSIZE_ARRAY = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
      public UInt32 LowPart;
      public UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
       public LUID Luid;
       public UInt32 Attributes;
    }


    public struct TOKEN_PRIVILEGES {
      public UInt32 PrivilegeCount;
      [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)]
      public LUID_AND_ATTRIBUTES [] Privileges;
    }

    [DllImport("advapi32.dll", SetLastError=true)]
     public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int
        SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);


    [DllImport("advapi32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetThreadToken(
      IntPtr PHThread,
      IntPtr Token
    );

    [DllImport("advapi32.dll", SetLastError=true)]
     [return: MarshalAs(UnmanagedType.Bool)]
      public static extern bool OpenProcessToken(IntPtr ProcessHandle, 
       UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
     public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
     ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
"@

  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent())
  if($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
    Write-Warning "Run the Command as an Administrator"
    Break
  }

  Add-Type -MemberDefinition $signature -Name AdjPriv -Namespace AdjPriv
  $adjPriv = [AdjPriv.AdjPriv]
  [long]$luid = 0

  $tokPriv1Luid = New-Object AdjPriv.AdjPriv+TokPriv1Luid
  $tokPriv1Luid.Count = 1
  $tokPriv1Luid.Luid = $luid
  $tokPriv1Luid.Attr = [AdjPriv.AdjPriv]::SE_PRIVILEGE_ENABLED

  $retVal = $adjPriv::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tokPriv1Luid.Luid)

  [IntPtr]$htoken = [IntPtr]::Zero
  $retVal = $adjPriv::OpenProcessToken($adjPriv::GetCurrentProcess(), [AdjPriv.AdjPriv]::TOKEN_ALL_ACCESS, [ref]$htoken)
  

  $tokenPrivileges = New-Object AdjPriv.AdjPriv+TOKEN_PRIVILEGES
  $retVal = $adjPriv::AdjustTokenPrivileges($htoken, $false, [ref]$tokPriv1Luid, 12, [IntPtr]::Zero, [IntPtr]::Zero)

  if(-not($retVal)) {
    [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
    Break
  }

  $process = (Get-Process -Name lsass)
  [IntPtr]$hlsasstoken = [IntPtr]::Zero
  $retVal = $adjPriv::OpenProcessToken($process.Handle, ([AdjPriv.AdjPriv]::TOKEN_IMPERSONATE -BOR [AdjPriv.AdjPriv]::TOKEN_DUPLICATE), [ref]$hlsasstoken)

  [IntPtr]$dulicateTokenHandle = [IntPtr]::Zero
  $retVal = $adjPriv::DuplicateToken($hlsasstoken, 2, [ref]$dulicateTokenHandle)

  $retval = $adjPriv::SetThreadToken([IntPtr]::Zero, $dulicateTokenHandle)
  if(-not($retVal)) {
    [System.Runtime.InteropServices.marshal]::GetLastWin32Error()
  }
}

#Vital, a TS must be running
try
{
    $TSEnv=New-Object -ComObject Microsoft.sms.tsenvironment
}
catch
{
    write-host ""
    write-host "Couldn't create the TSEnv ComObject."
    write-host "Is a task sequence currently running?"
    write-host "Exiting..."
    break
}

#Elevate to SYSTEM
Enable-TSDuplicateToken

$TSEnv3=New-TSEnv3
write-host ".EXAMPLE" -ForegroundColor DarkYellow
write-host "`$TSEnv3=New-TSEnv3" -ForegroundColor DarkYellow
write-host "`$TSEnv3.GetVariableValue('_SMSTSOrgName')" -ForegroundColor DarkYellow
Write-host "Output:" -ForegroundColor DarkYellow
#write-host "----------------" -ForegroundColor DarkYellow
$TSEnv3.GetVariableValue("_SMSTSOrgName")
$Mod=(Get-Module TSEnv3ModRCFinal)
write-host "Imported commands:" -ForegroundColor DarkYellow
$Mod.ExportedCommands.Keys