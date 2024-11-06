
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;


string encr=CreditCardEncryptor.EncryptCreditCardNumber("12345678912345");
Console.WriteLine(encr);

Console.WriteLine(CreditCardEncryptor.DecryptCreditCardNumber(encr));


public class CreditCardEncryptor
{
    // Replace this with a key from a secure source (e.g., Azure Key Vault).
    private static readonly byte[] Key = GenerateRandomBytes(32);// Convert.FromBase64String("YourBase64Encoded32ByteKey==");

      public static byte[] GenerateRandomBytes(int length)
    {
        byte[] randomBytes = new byte[length];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        return randomBytes;
    }
    public static string EncryptCreditCardNumber(string creditCardNumber)
    {
         if (Key.Length != 32)
        {
            throw new ArgumentException("Key must be 32 bytes for AES-256.");
        }
        using (Aes aes = Aes.Create())
        {
            aes.Key = Key;
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream())
            {
                ms.Write(aes.IV, 0, aes.IV.Length);  // Prepend IV to ciphertext for decryption
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                using (var writer = new StreamWriter(cs))
                {
                    writer.Write(creditCardNumber);
                }
                
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }

    public static string DecryptCreditCardNumber(string encryptedData)
    {
        byte[] fullCipher = Convert.FromBase64String(encryptedData);
        using (Aes aes = Aes.Create())
        {
            var blockSize=aes.BlockSize / 8;
            aes.Key = Key;
            aes.IV = fullCipher[..blockSize]; // Extract IV from the beginning
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream(fullCipher[blockSize..]))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var reader = new StreamReader(cs))
            {
                return reader.ReadToEnd();
            }
        }
    }
}
