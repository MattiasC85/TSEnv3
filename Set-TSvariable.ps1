Param (
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$true)]
   [string] $VarName,
   [Parameter(ValueFromPipelineByPropertyName,Mandatory=$true)]
   [string] $VarValue
)

#--------------------------------------------
# Script:Set-TSVariable.ps1
#
#
#
#
#--------------------------------------------

$block = @'
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$####$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$#,,,,,,,,,,,,,,|i:,,,,,,,,,,,,,,,,,,,,,,,,;$|,,,,,h$$$$:,,,,,,,,,,+$$$$$$$:,,,,,::.      .=h$$$$$$$$$$$$$$$
$$$$$$$$$$$$#                                         ,$=      i$$$.          .$$$$$$h      i           .O$$$$$$$$$$$$$
$$$$$$$$$$$$#                                         ,$=       =$$.    :      h$$$$$:     ,E,;|ii;      ,$$$$$$$$$$$$$
$$$$$$$$$$$$$|||:     =|||=       ;|||||     ,||||||||I$=        :#.    =i     :$$$$H      h$$$$$$$i     .$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$I     #$$$$:      i$$$$$     =$$$$$$$$$$=         .     =$.     O$$$;     ,$$$$HhhI.     +$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$I     #$$$$#:      ,O$$$           |$$$$=               =$I     =$$E      H$$$#        |O$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$I     #$$$$$$|       h$$           i$$$$=               =$$.     E$|     :$$$$#         |#$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$I     #$$$$$$$O.      E$     =$$$$$$$$$$=     ,         =$$+     i#      O$$$$$#$$E|     ,$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$I     ;;;;;;;;;       |$     .;;;;;;;;;;,    .#;        =$$$,     i     ;$$$##$$$$$h      E$$$$$$$$$$$$
$$$$$$$$$$$$$$$$I                     =$                     .$$|       =$$$h           O$$$H  ,::.      .$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$I                    .O$                     .$$$+      =$$$$,         =$$$$H           ,O$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$h;;;;;;;;;;;;;;;;;;=+#$$;;;;;;;;;;;;;;;;;;;;;=$$$$H;;;;;i$$$$H;;;;;;;;;E$$$$E|;:,...,;iH$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

'@

$signature=@'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.MemoryMappedFiles;
using Microsoft.Win32;
using Microsoft.CSharp.RuntimeBinder;

namespace SetTsVariable
{
	public class OverWrite
	{


	public static byte[] StrToByteArray(string str)
        {
            var dd = "";
            Dictionary<string, byte> hexindex = new Dictionary<string, byte>();
            for (int i = 0; i <= 255; i++)
                hexindex.Add(i.ToString("X2"), (byte)i);

            List<byte> hexres = new List<byte>();
            for (int i = 0; i < str.Length; i += 2)
            {
                if (str.Substring(i, 2) != "00")
                {
                    dd = str.Substring(i, 2);

                    hexres.Add(hexindex[str.Substring(i, 2)]);
                }
            }

            return hexres.ToArray();
        }

            int FindBytes(byte[] src, byte[] find)
            {
                int index = -1;
                int matchIndex = 0;
                // handle the complete source array
                for (int i = 0; i < src.Length; i++)
                {
                    if (src[i] == find[matchIndex])
                    {
                        if (matchIndex == (find.Length - 1))
                        {
                            index = i - matchIndex;
                            break;
                        }
                        matchIndex++;
                    }
                    else if (src[i] == find[0])
                    {
                        matchIndex = 1;
                    }
                    else
                    {
                        matchIndex = 0;
                    }

                }
                return index;
            }

            byte[] ReplaceBytes(byte[] src, byte[] search, byte[] repl)
            {
                byte[] dst = null;
                int index = FindBytes(src, search);
                if (index >= 0)
                {
                    dst = new byte[src.Length - search.Length + repl.Length];
                    // before found array
                    Buffer.BlockCopy(src, 0, dst, 0, index);
                    // repl copy
                    Buffer.BlockCopy(repl, 0, dst, index, repl.Length);
                    // rest of src array
                    Buffer.BlockCopy(
                        src,
                        index + search.Length,
                        dst,
                        index + repl.Length,
                        src.Length - (index + search.Length));
                }
                return dst;
            }
            public bool overwriteProtectedVariable(string variableName, string variableValue)
            {
				
				Type objType = Type.GetTypeFromProgID("Microsoft.SMS.TSEnvironment");
				
				if (objType == null)
				{
					Console.WriteLine("Could not find the TSEnvironment, is this running inside a Task Sequence?");
					return false;
				}
				dynamic TSEnv = System.Activator.CreateInstance(objType);

                var tst = TSEnv.GetVariables();

		        //Fixes capital/lowercase spellings
                foreach (string varListName in tst)
                {
                    //varListName = varListName.ToLower();
                    if (varListName.ToLower() == (variableName.ToLower()))
                    {
                        variableName= varListName;
                        
                    }
                }
                string FileMapGuid = JustInCaseRegistry();
                if (FileMapGuid == "NotFound")
                {
                    Console.WriteLine("Could not find the path for the MemoryMappedFile");
                    return false;
                }
                var mappedFile2 = System.IO.MemoryMappedFiles.MemoryMappedFile.OpenExisting(FileMapGuid, MemoryMappedFileRights.ReadWrite);

                //Console.write(TSEnv.GetVariables());

                var Viewacc2 = mappedFile2.CreateViewAccessor();
                var size = Viewacc2.Capacity;
                bool triedTo = false;
                byte[] SearchByte = new byte[] { 83, 77, 83, 84, 83 };

                byte[] ByteArray = new byte[size];
                byte[] Restore = new byte[size];
                string input = variableName;
		        //Console.writeLine("input"+input);
                string editedname = input.Replace("_", "") + "_";
                //Console.writeLine("Changing " + input + " to " + variableValue +".");
                //Console.writeLine(editedname);
                byte[] Stringarray = Encoding.UTF8.GetBytes(input);
                byte[] replaceWith = Encoding.UTF8.GetBytes(editedname);
                //Stream View2 = mappedFile2.CreateViewStream();
                using (Stream view = mappedFile2.CreateViewStream())
                {
                    //Console.writeLine("After View");

                    //Stores the memorymappedfile in ByteArray
                    var read = view.Read(ByteArray, 0, ByteArray.Count());

                    //read.Wait(); ReadAsync. v4.5

                    int lastIndex = Array.FindLastIndex(ByteArray, by => by != 0);
                    Array.Resize(ref ByteArray, lastIndex + 1);
                    //Console.writeLine(ByteArray.Length);

                    //Searches for the variable name in ByteArray and, if found, creates a new byte array with the variable renamed to var_.
                    var hit = ReplaceBytes(ByteArray, Stringarray, replaceWith);
                    
                    if (hit != null)
                    {
                        //Console.writeLine("Found the variable " + variableName);
                        //Console.writeLine("Current value of " + variableName + " = " + )
                        //Console.writeLine((TSEnv[variableName]));
                        //Console.writeLine("The current value of " + variableName + " is " + TSEnv[variableName]);

                        //Writes the byte array to the mappedfile
                        Viewacc2.WriteArray(0, hit, 0, hit.Length);

                        var TSVariable = TSEnv[editedname];

                        //Uses the COM-object TSEnv to verify that the variable is renamed.
                        if (TSVariable != null)
                        {
                            //Console.writeLine("Successfully changed the name to " + editedname);
                            //Console.writeLine("Setting the value to " + variableValue);
                            

                            //Using the COM-object after renaming the variable since I havn't found a way to decode the value
                            try
                            {
                            TSEnv.Value[editedname] = variableValue;
                            //Console.WriteLine("After TSEnv");
                            
                            Stream view3 = mappedFile2.CreateViewStream();

                            //After setting the value, store the new byte array, needed in order the change the variable name back to what it was
                            var read2 = view3.Read(Restore, 0, Restore.Count());
                            
                            int lastIndex2 = Array.FindLastIndex(Restore, by => by != 0);
                            Array.Resize(ref Restore, lastIndex2 + 1);
                            }
                            catch
                            {
                            //Console.writeLine("1");
                            }
                            
                            //File.WriteAllBytes("C:\\temp\\Restore.log", Restore);

                        }
                        else
                        {
                            Console.WriteLine("Did not succeed to set the name of " + variableName + " to " + editedname);
                        }

                    }
                    else
                    {
                        Console.WriteLine("Did not find the variable " + variableName);
                        //File.WriteAllBytes("D:\\temp\\out2.log", ByteArray);
                    }
                    byte[] restore2;

                    //If the varible was found earlier
                    if (hit != null)
                    {
                        //Console.writeLine("Restore, hit1 not null");
                        //Console.writeLine(editedname);
                        //Console.writeLine(input);
                     

                        //Change the variable name back to what it was.
			            restore2 = ReplaceBytes(Restore, replaceWith, Stringarray);
                        triedTo = true;
                    }
                    else
                    {
                        //Restore the mappedfile back to its orginal state on error. Just in case
                        //Console.writeLine("Restoring variables, could not find the variable name.");
                        restore2 = ReplaceBytes(ByteArray, replaceWith, Stringarray);
                    }

                    //Writes the final byte array to the mappedfile
                    if (restore2 != null)
                        {
                            Viewacc2.WriteArray(0, restore2, 0, restore2.Length);

                        //Verify that the variable has the (new) expected value
                        if (triedTo == true)
                        {
                            if ((TSEnv[variableName]) == variableValue)
                            {
                                Console.WriteLine("Success. " + variableName + "=" + variableValue);
                            }
                        }
                            //File.WriteAllBytes("C:\\temp\\ByteArray.log", ByteArray);
                            //File.WriteAllBytes("C:\\temp\\Restore2", restore2);
                        }
                    

                }
                    return true;
            }
            string JustInCaseRegistry()
            {
		    //Always found the same object but just in case MS changes it the object can be found under this key, at least atm.
		    //eg. 		47006C006F00620061006C005C007B00350031004100300031003600420036002D0046003000440045002D0034003700350032002D0042003900370043002D003500340045003600460033003800360041003900310032007D00
		    //It's a Hexstring   G   l  o   b   a   l   \   {   5   1   A    
                    const string subkey = "SOFTWARE\\Microsoft\\SMS";
                    RegistryKey registryKey = Registry.LocalMachine.OpenSubKey(subkey);
                    string GlobalObject = "NotFound";
                    int i = 0;
                    foreach (var Childkey in registryKey.GetSubKeyNames())
                    {
                        if (Childkey.Length.Equals(180))
                        {
                            i++;
                            var tmpbyte = StrToByteArray(Childkey);
                            var GlobalObjectName = System.Text.Encoding.UTF8.GetString(tmpbyte);
                            //Console.writeLine(GlobalObjectName);
                            var filename = "D:\\Temp\\Dump" + i.ToString() + ".log";
                            var foundObject = Objecttest(GlobalObjectName, filename);
                            if (foundObject == true)
                            {
                            //Console.writeLine("Found Globalobject: " + GlobalObjectName);
                            //Console.writeLine(Childkey);
                            GlobalObject = GlobalObjectName;
                            return GlobalObject;
                            }

                        }
                    }
                return GlobalObject;
                }

            bool Objecttest(string objectName, string filename)
            {
		//Parses the reg-node and tries to verify which one that is the correct key.
                try
                {
                    var mappedFile2 = System.IO.MemoryMappedFiles.MemoryMappedFile.OpenExisting(objectName, MemoryMappedFileRights.ReadWrite);
                    var Viewacc2 = mappedFile2.CreateViewAccessor();
                    var size = Viewacc2.Capacity;
		            //83,77,83,84,83="SMSTS" Used to find the correct MemoryMap
                    byte[] SearchByte = new byte[] { 83, 77, 83, 84, 83 };
                    byte[] ByteArray = new byte[size];
                    byte[] Restore = new byte[size];
                    using (Stream view = mappedFile2.CreateViewStream())
                    {
                        
                        var read = view.Read(ByteArray, 0, ByteArray.Count());
                        //read.Wait(); ReadAsync. v4.5
			//Remove trailing zeroes, good if you want to dump the bytearray to a file.
                        int lastIndex = Array.FindLastIndex(ByteArray, by => by != 0);
                        Array.Resize(ref ByteArray, lastIndex + 1);
			//Search for "SMSTS"
                        var Hit = FindBytes(ByteArray, SearchByte);
                        if (Hit == -1)
                        {
                            return false;
                        }

                    }
                }
                catch
                {
                    return false;
                }
                    return true;
            }
     }
}
'@



#try 
#{ 
#[SetTsVariable.OverWrite]
try
{
write-host $block -ForegroundColor White
Add-Type -TypeDefinition $signature -ReferencedAssemblies Microsoft.CSHARP
Start-Sleep -s 3
}
catch
{
Write-host "Error adding type"
}
$TSEnv3=New-Object SetTsVariable.OverWrite
$Success=$TSEnv3.overwriteProtectedVariable($VarName,$VarValue)

#Invoke-Command {$TSEnv3=New-Object SetTsVariable.OverWrite;$TSEnv3.overwriteProtectedVariable("_SMSTSLogPath","C:\Baaahhh!")}
#} 
#catch 
#{
#Start-Sleep -s 3
#Add-Type -TypeDefinition $signature -ReferencedAssemblies Microsoft.CSHARP
#}

#Add-Type -TypeDefinition $signature -ReferencedAssemblies Microsoft.CSHARP
#Invoke-Command {$TSEnv3=New-Object SetTsVariable.OverWrite;$TSEnv3.overwriteProtectedVariable($VarName,$VarValue)}

#Fungerar 10an
#[SetTsVariable.OverWrite]::new().overwriteProtectedVariable($VarName,$VarValue)

