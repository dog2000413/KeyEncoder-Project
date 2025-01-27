using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

public class KeyEncoder
{
    public static void Main(string[] args)
    {
        string inputFile;
        string outputFile;

        if (args.Length == 2)
        {
            inputFile = args[0];
            outputFile = args[1];
        }
        else
        {
            inputFile = "config.json";
            outputFile = "config.enc";
            Console.WriteLine("No arguments provided. Using default files:");
            Console.WriteLine($"Input File: {inputFile}");
            Console.WriteLine($"Output File: {outputFile}");
        }

        if (!File.Exists(inputFile))
        {
            Console.WriteLine("Could not find " + inputFile);
            return;
        }

        try
        {
            // 1) Read the plaintext JSON
            string plainJson = File.ReadAllText(inputFile);
            Console.WriteLine("Original JSON:");
            Console.WriteLine(plainJson);

            // 2) Parse JSON to get Url and Token
            var doc = JsonDocument.Parse(plainJson).RootElement;
            string url = doc.GetProperty("Url").GetString() ?? "";
            string token = doc.GetProperty("Token").GetString() ?? "";
            Console.WriteLine($"\nURL: {url}");
            Console.WriteLine($"Token: {token}");

            // 3) Generate a new 256-bit AES key (32 bytes)
            byte[] key = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }

            // 4) Convert the key to Base64 and store in key.txt
            string base64Key = Convert.ToBase64String(key);
            File.WriteAllText("key.txt", base64Key);
            Console.WriteLine($"\nGenerated Key (Base64): {base64Key}");
            Console.WriteLine("Saved key to key.txt");

            // 5) Encrypt the plaintext data
            byte[] encrypted = Encrypt(plainJson, key);

            // 6) Write the ciphertext to outputFile
            File.WriteAllBytes(outputFile, encrypted);
            Console.WriteLine($"Encryption complete. Created: {outputFile}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }

    private static byte[] Encrypt(string data, byte[] key)
    {
        using Aes aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using MemoryStream ms = new MemoryStream();
        // Write IV first
        ms.Write(aes.IV, 0, aes.IV.Length);

        using ICryptoTransform encryptor = aes.CreateEncryptor();
        using CryptoStream cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        byte[] plainBytes = System.Text.Encoding.UTF8.GetBytes(data);
        cryptoStream.Write(plainBytes, 0, plainBytes.Length);
        cryptoStream.FlushFinalBlock();

        return ms.ToArray();
    }
}
