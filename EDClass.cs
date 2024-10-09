using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;



namespace Encryption_Decryption
{
    public class EDClass
    {
        private static readonly byte[] iv = new byte[16];
        public static string EncryptString(string key, string plainText)
        {
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public static string DecryptString(string key, string cipherText)
        {
            byte[] buffer = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key);
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader((Stream)cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }

        // Encrypts a string (using user's credentials or machine scope)
        public static string NewEncryptString(string plainText)
        {
            try
            {
                if (string.IsNullOrEmpty(plainText))
                    throw new ArgumentException("plainText cannot be null or empty.");

                byte[] data = Encoding.UTF8.GetBytes(plainText);

                // Check if the data was converted properly
                if (data == null || data.Length == 0)
                    throw new Exception("Failed to convert string to byte array.");

                byte[] encrypted = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);

                // Check if encryption was successful
                if (encrypted == null || encrypted.Length == 0)
                    throw new Exception("Encryption failed, result is null or empty.");

                // Convert the encrypted byte array to a base64 string
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Encryption Error: " + ex.Message);
                return null;
            }
        }


        // Decrypts the encrypted string
        public static string NewDecryptString(string cipherText)
        {
            byte[] data = Convert.FromBase64String(cipherText);
            byte[] decrypted = ProtectedData.Unprotect(data, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(decrypted);
        }
    }
}
