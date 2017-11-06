// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace SmartcardLogon
{
    class Program
    {
        static void Main(string[] args)
        {
            //
            // 1. Call LogonUser with a basic username and password
            //
            string username = "user1";
            string domain = "contoso";
            PasswordFlow(username, domain);

            //
            // 2. Perform certificate marshaling of a given certificate, and
            //     then call Logon user with a generated PSCredential
            //
            string thumbprint = "mythumbprint";
            MarshalFlow(thumbprint);

            //
            // 3. Unmarshal a CERT_CRED_INFO blob from a PSCredential 'UserName' field, 
            //     and locate the original certificate 
            //
            string data = "certdata";
            // Note: If your code is consuming a PSCredential, then this data will come from the 'UserName' property
            //  i.e. string data = credentialObject.UserName (credentialObject is System.Management.Automation.PSCredential object) 
            ReverseMarshal(data);

            Console.Write("Press [Enter] to exit");
            Console.ReadLine();
        }

        /// <summary>
        ///  Perform a basic logon of the user provided, after collecting the user password 
        /// </summary>
        static void PasswordFlow(string username, string domain)
        {
            Console.Write("Enter Password: ");
            SecureString password = new SecureString();
            password = GetPasswordFromConsole(password);
            IntPtr bstrPassword = Marshal.SecureStringToBSTR(password);

            LogonCore(username, domain, bstrPassword);

            Marshal.ZeroFreeBSTR(bstrPassword);
        }

        /// <summary>
        /// Reverse marshal a CERT_CREDENTIAL_INFO struct, and locate the original certificate 
        /// </summary>
        /// <param name="data">A string of the encoded CERT_CREDENTIAL_INFO struct</param>
        static void ReverseMarshal(string data)
        {

            IntPtr credData = IntPtr.Zero;
            IntPtr credInfo = IntPtr.Zero;
            NativeMethods.CRED_MARSHAL_TYPE credType = 0;
            X509Store userMyStore = null;

            try
            {
                credData = Marshal.StringToHGlobalUni(data); 
                bool success = NativeMethods.CredUnmarshalCredential(credData, out credType, out credInfo);

                if (success)
                {
                    NativeMethods.CERT_CREDENTIAL_INFO certStruct = (NativeMethods.CERT_CREDENTIAL_INFO)(Marshal.PtrToStructure(credInfo, typeof(NativeMethods.CERT_CREDENTIAL_INFO)));

                    byte[] data2 = certStruct.rgbHashOfCert;
                    string hex = BitConverter.ToString(data2).Replace("-", string.Empty);

                    X509Certificate2 certCredential = new X509Certificate2();
                    userMyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    userMyStore.Open(OpenFlags.ReadOnly);
                    X509Certificate2Collection certsReturned = userMyStore.Certificates.Find(X509FindType.FindByThumbprint, hex, false);

                    if (certsReturned.Count == 0)
                    {
                        Console.WriteLine("Could not find the cert you want, aborting");
                        return;
                    }

                    certCredential = certsReturned[0];

                    Console.WriteLine("Located certificate");
                    Console.WriteLine("Subject: " + certCredential.Subject);
                    Console.WriteLine("SubjectName: " + certCredential.SubjectName);

                    foreach (X509Extension extension in certCredential.Extensions)
                    {
                        Console.WriteLine(extension.Oid.FriendlyName + "(" + extension.Oid.Value + ")");

                        AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
                        Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
                        Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
                        Console.ResetColor();
                        Console.WriteLine(asndata.Format(true));
                        Console.WriteLine(Environment.NewLine);
                    }

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
                if ( userMyStore != null )
                {
                    userMyStore.Close();
                }
            }
        }

        /// <summary>
        /// Locate a certificate in the User/My store by thumbprint, marshal the certificate into a CERT_CREDENTIAL_INFO 
        ///  struct, and then perform a LogonUser call with the certificate credential struct 
        /// </summary>
        /// <param name="thumbprint">The thumbprint of a certificate to marshal into a CERT_CREDENTIAL_INFO struct</param>
        static void MarshalFlow(string thumbprint)
        {
            //
            // Set up the data struct
            //
            NativeMethods.CERT_CREDENTIAL_INFO certInfo = new NativeMethods.CERT_CREDENTIAL_INFO();
            certInfo.cbSize = (uint)Marshal.SizeOf(typeof(NativeMethods.CERT_CREDENTIAL_INFO));

            //
            // Locate the certificate in the certificate store 
            //
            X509Certificate2 certCredential = new X509Certificate2();
            X509Store userMyStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            userMyStore.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certsReturned = userMyStore.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
            userMyStore.Close();

            if (certsReturned.Count == 0)
            {
                Console.WriteLine("Could not find the cert you want, aborting");
                return;
            }

            //
            // Marshal the certificate 
            //
            certCredential = certsReturned[0];
            certInfo.rgbHashOfCert = certCredential.GetCertHash();
            int size = Marshal.SizeOf(certInfo);
            IntPtr pCertInfo = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(certInfo, pCertInfo, false);
            IntPtr marshaledCredential = IntPtr.Zero;
            bool result = NativeMethods.CredMarshalCredential(NativeMethods.CRED_MARSHAL_TYPE.CertCredential, pCertInfo, out marshaledCredential);

            string certBlobForUsername = null;
            PSCredential psCreds = null;

            if (result)
            {
                certBlobForUsername = Marshal.PtrToStringUni(marshaledCredential);
                psCreds = new PSCredential(certBlobForUsername, new SecureString());
            }

            Marshal.FreeHGlobal(pCertInfo);
            if (marshaledCredential != IntPtr.Zero)
            {
                NativeMethods.CredFree(marshaledCredential);
            }
                
            Console.WriteLine("Certificate Credential Data: " + certBlobForUsername);
            CertFlow(certBlobForUsername);
        }

        /// <summary>
        /// Perform the core LogonUser logic, including basic error handling 
        /// </summary>
        /// <param name="username">The name of the user to logon</param>
        /// <param name="domain">The domain of the user to logon</param>
        /// <param name="creds">A credential object</param>
        static void LogonCore(string username, string domain, IntPtr creds)
        {
            IntPtr tokenHandle = IntPtr.Zero;

            var logonType = LogonType.LOGON32_LOGON_NETWORK_CLEARTEXT;
            // This logon type preserves the name and password in the authentication package, which allows the server to make connections 
            //  to other network servers while impersonating the client. A server can accept plaintext credentials from a client, 
            //  call LogonUser, verify that the user can access the system across the network, and still communicate with other servers.
            //  https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx 

            int logonProvider = (logonType == LogonType.LOGON32_LOGON_NEW_CREDENTIALS) ? NativeMethods.LOGON32_PROVIDER_WINNT50 : NativeMethods.LOGON32_PROVIDER_DEFAULT;

            bool logonWorked = NativeMethods.LogonUser(
                           username,
                           domain,
                           creds,
                           (int)logonType,
                           logonProvider,
                           ref tokenHandle
                           );

            if (logonWorked)
            {
                Console.WriteLine();
                Console.WriteLine("User Logon Success!");
            }
            else
            {
                int lastErr = Marshal.GetLastWin32Error();
                Console.WriteLine();
                Console.WriteLine("Could not log user on. Error: " + lastErr);
                if (lastErr == 1326)
                {
                    Console.WriteLine("The username or password is incorrect");
                }
                if (lastErr == 1385)
                {
                    Console.WriteLine("Logon failure: the user has not been granted the requested logon type at this computer.");
                }
            }
        }

        /// <summary>
        /// Perform a Logon User call with a certificate blob as the 'username' field of a PSCredential. 
        ///  Collect the PIN of the PIN-protected logon cert the same way we collect password 
        /// </summary>
        /// <param name="username">A string of the encoded CERT_CREDENTIAL_INFO struct</param>
        static void CertFlow(string username)
        {
            SecureString pin = new SecureString();
            pin = GetPasswordFromConsole(pin);
            IntPtr bstrPin = Marshal.SecureStringToBSTR(pin);
            LogonCore(username, null, bstrPin);
        }

        /// <summary>
        /// Perform a Logon User call with a certificate blob as the 'username' field of a PSCredential. 
        ///  Do not collect a PIN, as this certificate is not a PIN-protected logon cert 
        /// </summary>
        /// <param name="username"></param>
        static void CertFlowNoPin(string username)
        {
            SecureString pin = new SecureString();
            IntPtr bstrPin = Marshal.SecureStringToBSTR(pin);
            LogonCore(username, null, bstrPin);
        }

        /// <summary>
        ///  Get a SecureString password from console input 
        /// </summary>
        /// <param name="password"></param>
        /// <returns>A ReadOnly SecureString password</returns>
        static SecureString GetPasswordFromConsole(SecureString password)
        {
            ConsoleKeyInfo nextKey = Console.ReadKey(true);

            while (nextKey.Key != ConsoleKey.Enter)
            {
                if (nextKey.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.RemoveAt(password.Length - 1);
                        // erase the last * as well
                        Console.Write(nextKey.KeyChar);
                        Console.Write(" ");
                        Console.Write(nextKey.KeyChar);
                    }
                }
                else
                {
                    password.AppendChar(nextKey.KeyChar);
                    Console.Write("*");
                }
                nextKey = Console.ReadKey(true);
            }
            password.MakeReadOnly();

            return password;
        }
    }
}
