# TSEnv3
Overwrite ANY writeprotected TSEnvironment variable in SCCM.

Version 0.6
* Fixed varname matching multiple names.


Open Source alternative to TSEnv2.
![alt text](https://raw.githubusercontent.com/MattiasC85/TSEnv3/master/TSEnv3_2.png)
Use:
Eg.
Set-TSVariable.ps1 -VarName _SMSTSOrgName -VarValue 2NdSite

Must be run during a TS under the local system account.

I'm no programmer. I'm just a guy who got this to work.
This is a stripped down version of the .exe I've made.

My initial idea was to convert the c# class and make it all powershell.
Snow and the fact that my wife is giving birth to our 3rd child, within 3 years, in only a week or two made me cut some corners, and after all, powershell is .NET.

There are probably a lot I've could have done better but it does what it is supposed to.


Also, this is "AsIs", there are plenty of fixes to be made not to mention verifying all kinds of charsets (UTF8/UNICODE/ASCII).
But it's open source, you do what ever you want to with it. I've tried to make comments on the most criticle parts of the script.
Feel free to open an issue though, might help other ppl if there's a quick fix :)

Tested on Win 7 (Powershell 3.0 minimum), WinPE 10 and Windows 10 (Powershell 5).

Todo:

*Edit normal variables.

*Powershell version check.

*Get my pregnant wife happy. (Might take some time)

*Impersonate local system when running as admin.

*Fix Text Encoding.
