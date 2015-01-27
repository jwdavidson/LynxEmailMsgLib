using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace LynxEmailMsgLib.Crypto
{
    public static class AesUtilities
    {
        public static byte[] EncryptStringToByteArray(string stringToEncrypt, byte[] key, byte[] iv)
        {
            // Check arguments
            if (string.IsNullOrEmpty(stringToEncrypt))
                throw new ArgumentNullException("bytesToEncrypt");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");

            byte[] encrypted;

            // create the encryption algorithm object with the specified key and iv
            using (AesManaged aes = new AesManaged { Key = key, IV = iv }) {
                // create an encryptor to perform the stream transform
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                    // create the streams used for encryption
                using (MemoryStream memoryStream = new MemoryStream()) {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)) {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream)) {

                            // write all the data to the stream
                            streamWriter.Write(stringToEncrypt);
                        }
                        // return the encrypted byte array from the memory stream
                        encrypted = memoryStream.ToArray();
                    }
                }
            }
            return encrypted;
        }

        public static string DecryptByteArrayToString(byte[] cipherText, byte[] key, byte[] iv)
        {
            // Check arguments
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");
            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException("iv");

            string plainText = null;

            // create the encryption algorithm object with the specified key and iv
            using (AesManaged aes = new AesManaged { Key = key, IV = iv }) {
                // create an encryptor to perform the stream transform
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                // create the streams used for encryption
                using (MemoryStream memorySteam = new MemoryStream(cipherText)) {
                    using (CryptoStream cryptoStream = new CryptoStream(memorySteam, decryptor, CryptoStreamMode.Read)) {
                        using (StreamReader streamReader = new StreamReader(cryptoStream)) {

                            // read the decrypted bytes from the decryption stream, placing them in a string
                            plainText = streamReader.ReadToEnd();
                        }
                    }
                }
            }
            return plainText;
        }
    }
}
