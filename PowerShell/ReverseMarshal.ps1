[string] $SourceCode = @"
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Management.Automation;

namespace Bongiovi.SmartcardLogon
{
    public static class SmartcardCredManager
    {
        public enum CRED_MARSHAL_TYPE
        {
            CertCredential = 1,
            UsernameTargetCredential
        }

        public const int CERT_HASH_LENGTH = 20;

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_CREDENTIAL_INFO
        {
            public uint cbSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] rgbHashOfCert;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CredUnmarshalCredential(
            IntPtr MarshaledCredential,
            out CRED_MARSHAL_TYPE CredType,
            out IntPtr Credential
        );

        public static string ReverseMarshal(string data)
        {

            IntPtr credData = IntPtr.Zero;
            IntPtr credInfo = IntPtr.Zero;
            CRED_MARSHAL_TYPE credType = 0;

            try
            {
                credData = Marshal.StringToHGlobalUni(data); 
                bool success = CredUnmarshalCredential(credData, out credType, out credInfo);

                if (success)
                {
                    CERT_CREDENTIAL_INFO certStruct = (CERT_CREDENTIAL_INFO)(Marshal.PtrToStructure(credInfo, typeof(CERT_CREDENTIAL_INFO)));

                    byte[] data2 = certStruct.rgbHashOfCert;
                    string hex = BitConverter.ToString(data2).Replace("-", string.Empty);
                    return hex;
                }
            }
            catch(Exception e)
            {
                Console.WriteLine("An error occured: " + e.Message + e.StackTrace);
            }
            finally
            {
                Marshal.FreeHGlobal(credData);
                Marshal.FreeHGlobal(credInfo);
            }
            return null;
        }
    }
}
"@

add-type -AssemblyName System;
add-type -AssemblyName System.Runtime.InteropServices;
add-type -AssemblyName System.Security;
add-type -AssemblyName System.Management.Automation;
add-type -TypeDefinition $SourceCode -Language CSharp

$smartcardCred = Get-Credential
$certThumbprint = [Bongiovi.SmartcardLogon.SmartcardCredManager]::ReverseMarshal($smartcardCred.UserName);

$certsReturned = Get-ChildItem cert:\currentuser\my\$certThumbprint

if ($certsReturned.Count -eq 0)
{
    Write-Error "Could not find the cert you want, aborting";
    return;
}

$certCredential = $certsReturned[0];

Write-Output "Located certificate";
Write-Output "Subject: " $certCredential.Subject;
Write-Output "SubjectName: " $certCredential.SubjectName.Name;
Write-Output "`r`n"
Write-Output "Extension OIDs:"

foreach ($extension in $certCredential.Extensions)
{
    Write-Output $extension.Oid.FriendlyName $extension.Oid.Value;
    Write-Output "`r`n"
}