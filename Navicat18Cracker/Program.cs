using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using SimpleBase;

namespace Navicat18Cracker;

class Program
{
    private static string NewPublicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1dqF3SkCaAAmMzs889I
qdW9M2dIdh3jG9yPcmLnmJiGpBF4E9VHSMGe8oPAy2kJDmdNt4BcEygvssEfginv
a5t5jm352UAoDosUJkTXGQhpAWMF4fBmBpO3EedG62rOsqMBgmSdAyxCSPBRJIOF
R0QgZFbRnU0frj34fiVmgYiLuZSAmIbs8ZxiHPdp1oD4tUpvsFci4QJtYNjNnGU2
WPH6rvChGl1IRKrxMtqLielsvajUjyrgOC6NmymYMvZNER3htFEtL1eQbCyTfDmt
YyQ1Wt4Ot12lxf0wVIR5mcGN7XCXJRHOFHSf1gzXWabRSvmt1nrl7sW6cjxljuuT
awIDAQAB
-----END PUBLIC KEY-----
""";

    private static string NewPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIIEOwIBADANBgkqhkiG9w0BAQEFAASCBCUwggQhAgEAAoIBAQDDV2oXdKQJoACY
zOzzz0ip1b0zZ0h2HeMb3I9yYueYmIakEXgT1UdIwZ7yg8DLaQkOZ023gFwTKC+y
wR+CKe9rm3mObfnZQCgOixQmRNcZCGkBYwXh8GYGk7cR50bras6yowGCZJ0DLEJI
8FEkg4VHRCBkVtGdTR+uPfh+JWaBiIu5lICYhuzxnGIc92nWgPi1Sm+wVyLhAm1g
2M2cZTZY8fqu8KEaXUhEqvEy2ouJ6Wy9qNSPKuA4Lo2bKZgy9k0RHeG0US0vV5Bs
LJN8Oa1jJDVa3g63XaXF/TBUhHmZwY3tcJclEc4UdJ/WDNdZptFK+a3WeuXuxbpy
PGWO65NrAgMBAAECggEAGUMDa950AGawp4nEgOrW1zEvfLo9qNW/YWBGEHyvrFLH
JZNAmj8ob842AY0kVg09iBt0kAO0JPe++k07B3NhrjIt6XOvvdVAoNFi2YImpinQ
vc49cDTH8uT4IFw2QnfrV1gpsQlaTPupnLjjw/dxK8mEEP8i4BdVm3CtzMj0/LvI
K4z+Nzgu5WRpuc9JIaIOY6OtJAoePVr0+80uBoZ1v/S9uZucWSkwYbM+iSz71C8x
5swsAjCw3R/1DCFvTOdCL0qHbB3txjkj95PqPdRv4S4Xdo37MK0M+YKBHyaPnGnJ
ffJuH8NRsaw6wzCvDlI5bLrNytxbt0erw6EQPq6L4QICAf0Cgf9iPxOpOCY+LUQy
soI9Q4mjX+5/ctBzvIxgfwZClVPJ+zwsSyzNHlEeDeRPuXaXl+hjyVTbCLsiR4Me
DaQ3aBPTiw1bP9y3s6F5e8O4t37KtELlCRCJxt1PQLyj6YG4SdYaeTaTDuTY22pD
3fWChYr0EChu0aNDi+GpnWhbnB1s56FOwGDdj84uE04DgPZcy63fdGZx1lLs5I2E
s3P8LN56MEXAGHU9CjNvfLOm56E2xuCv3DSWdyLQT75rNZyEQYjVz6hWqpZ5Ydr+
lCf6E/Sggt776OSyuutD5G7QevU8u+DH5CHFMLASVdCj/GZGPMPLLZtUO8yqYnDi
cd2T04cCAgExAoH/UP9t5zJKnTJWqnFvXLDktdPuXha7ct+84AV5lMVmCfzeVCo6
KnXXLK8JTw05j6uGxVYEZnyhQ5avq8RVYfSle9+FSHizMKSg+PYnm490sgvBpvA9
OUnBxYg6vexSrSv6n2LVspIx6/OhfYht04jj0WnM2+hr8NFPX7ZNhlGEFPg2jiWe
9quLsYLq64qUElc95x8hIrMvNO0NG52TfxFC7nwD1WaUqZlSZJTrzCvlRrLaJUKn
/HEGO7Wy6NKPUp5xAM2uHJ2RZ0tc8EwXVV7EbNzYl9kfS5c9RYD8N1dX/hVrMYGM
sfT9BHDJjZkWfMu2JDlaeSzABK0aIib8JdbbAgIAyw==
-----END PRIVATE KEY-----
""";

    static bool IsRunAsAdmin()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    static void Main(string[] args)
    {
        if (!IsRunAsAdmin())
        {
            Console.WriteLine("PLEASE RUN AS ADMINISTRATOR");
            return;
        }

        // Patch
        Console.WriteLine("=== START THE PATCHING PROCESS");
        PatchHosts();
        PatchLibcc();

        // Keygen
        Console.WriteLine("=== START THE OFFLINE ACTIVATION PROCESS");
        var sn = GenerateKey(GetLanguage(), GetProduct());
        var chunks = sn
            .ToCharArray()
            .Select((x, i) => new { x, i })
            .GroupBy(p => p.i / 4, p => p.x)
            .Select(chunk => new string(chunk.ToArray()));
        var formattedSn = string.Join("-", chunks);
        Console.WriteLine("SN: " + formattedSn);
        Console.WriteLine("Request Code:");
        var requestCode = Console.ReadLine();
        var reqContent = DecryptByRSAFromBase64(requestCode);
        Console.WriteLine("Plain request:" + reqContent);
        var req = JsonConvert.DeserializeObject<LicenseRequest>(reqContent);
        var resp = req.toResponse(GetName(), GetOrganization());
        var respContent = String.Format("{{\"K\":\"{0}\", \"DI\":\"{1}\", \"N\":\"{2}\", \"O\":\"{3}\", \"T\":{4}}}",
            resp.K, resp.DI, resp.N, resp.O, resp.T);
        Console.WriteLine("Plain response:" + respContent);
        var respCode = CryptByRSAToBase64(respContent);
        Console.WriteLine("Activation Code:");
        Console.WriteLine(respCode);

        Console.WriteLine("Press any key to continue...");
        Console.ReadKey();
    }

    private static void RemoveReadonly(string filePath)
    {
        FileAttributes attributo = File.GetAttributes(filePath);
        if ((attributo & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
        {
            File.SetAttributes(filePath, attributo ^ FileAttributes.ReadOnly);
        }
    }

    public static void PatchHosts()
    {
        var hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts");
        RemoveReadonly(hostsPath);
        var hostsContent = File.ReadAllLines(hostsPath);
        foreach (var line in hostsContent)
        {
            if (line.Contains("activate.navicat.com"))
            {
                Console.WriteLine("Activation site has been banned");
                return;
            }
        }

        using (var sw = File.AppendText(hostsPath))
        {
            sw.WriteLine();
            sw.WriteLine("# navicat");
            sw.WriteLine("127.0.0.1 activate.navicat.com");
            sw.Flush();
        }

        Console.WriteLine("Activation site has been banned");
    }

    static string GetInstallLocation()
    {
        while (true) {
            Console.WriteLine("Installation Path:");
            var location = Console.ReadLine()?.Trim();
            if (!string.IsNullOrEmpty(location))
            {
                return location;
            }
        }
    }

    static int GetPositionAfterMatch(byte[] data, byte[] pattern, int offset = 0)
    {
        for (int i = 0 + offset; i < (data.Length - pattern.Length); i++)
        {
            bool match = true;
            for (int k = 0; k < pattern.Length; k++)
            {
                if (data[i + k] != pattern[k])
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                return i + pattern.Length;
            }
        }

        return -1;
    }

    static void PatchLibcc()
    {
        Console.WriteLine($"Try patch navicat-v18 libcc");
        //MI..IB..
        byte[] firstPattern = [0x4D, 0x49, 0x00, 0x00, 0x49, 0x42, 0x00, 0x00];
        var libccPath = Path.Combine(GetInstallLocation(), "libcc.dll");
        RemoveReadonly(libccPath);

        var libccBytes = File.ReadAllBytes(libccPath);
        var publicKeyStartLocation = GetPositionAfterMatch(libccBytes, firstPattern);
        if (publicKeyStartLocation <= 0)
        {
            Console.WriteLine("The starting position of the public key was not found");
            return;
        }

        publicKeyStartLocation -= firstPattern.Length;
        //Qa..
        byte[] secondPattern = [0x51, 0x61, 0x00, 0x00];
        var publicKeyPatchLocation = GetPositionAfterMatch(libccBytes, secondPattern, publicKeyStartLocation);
        if (publicKeyPatchLocation <= 0)
        {
            Console.WriteLine("The patching position of the public key was not found");
            return;
        }

        publicKeyPatchLocation -= secondPattern.Length;

        if (publicKeyPatchLocation - publicKeyStartLocation > 0x100)
        {
            Console.WriteLine(
                $"The starting position of the public key(0x{publicKeyStartLocation.ToString("X")})is far from feature poisition(0x{publicKeyPatchLocation.ToString("X")}), it may have been patched");
            return;
        }

        libccBytes[publicKeyPatchLocation] = 0x54; // Q -> T
        File.WriteAllBytes(libccPath, libccBytes);
        Console.WriteLine("libcc has been patched");
    }

    static string GetLanguage()
    {
        while (true)
        {
            Console.WriteLine("Language(cn/en):");
            var language = Console.ReadLine()?.Trim();
            if (language == "cn" || language == "en")
            {
                return language;
            }
        }
    }

    static string GetProduct()
    {
        while (true)
        {
            Console.WriteLine("Product(Premium/SQLite):");
            var product = Console.ReadLine()?.Trim();
            if (product == "Premium" || product == "SQLite")
            {
                return product;
            }
        }
    }

    static string GetName()
    {
        while (true)
        {
            Console.WriteLine("Name:");
            var name = Console.ReadLine()?.Trim();
            if (!string.IsNullOrEmpty(name))
            {
                return name;
            }
        }
    }

    static string GetOrganization()
    {
        while (true)
        {
            Console.WriteLine("Organization:");
            var org = Console.ReadLine()?.Trim();
            if (!string.IsNullOrEmpty(org))
            {
                return org;
            }
        }
    }

    private static String GenerateKey(string language, string product)
    {
        var random = new Random();
        var snBytes = new byte[10];
        // h*
        snBytes[0] = 0x68;
        snBytes[1] = 0x2a;

        snBytes[2] = (byte)random.Next(0, 256);
        snBytes[3] = (byte)random.Next(0, 256);
        snBytes[4] = (byte)random.Next(0, 256);

        if (language == "en")
        {
            snBytes[5] = 0xAC;
            snBytes[6] = 0x88;
        }
        else if (language == "cn")
        {
            snBytes[5] = 0xCE;
            snBytes[6] = 0x32;
        }
        else
        {
            throw new ArgumentException("Unsupported language");
        }

        if (product == "Premium")
        {
            snBytes[7] = 0x65;
        }
        else if (product == "SQLite")
        {
            snBytes[7] = 0x78;
        }
        else
        {
            throw new ArgumentException("Unsupported product");
        }

        snBytes[8] = (byte)(0x20);
        snBytes[9] = 0xFF;

        byte[] desKey = [0xE9, 0x7F, 0xB0, 0x60, 0x77, 0x45, 0x90, 0xAE];
        var encrypt = DesEncrypt(snBytes[2..], desKey);
        var target = new byte[10];
        target[0] = 0x68;
        target[1] = 0x2a;
        Array.Copy(encrypt, 0, target, 2, 8);
        return Base32.Rfc4648.Encode(target);
    }

    private static byte[] DesEncrypt(byte[] data, byte[] key)
    {
        using DESCryptoServiceProvider des = new DESCryptoServiceProvider();
        des.Key = key;
        des.Mode = CipherMode.ECB;
        des.Padding = PaddingMode.PKCS7;
        using var encryptor = des.CreateEncryptor();
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }


    private static byte[] DecryptByRSA(byte[] data)
    {
        RsaPrivateCrtKeyParameters priKey;
        using (var reader = new StringReader(NewPrivateKey))
            priKey = ((RsaPrivateCrtKeyParameters)new PemReader(reader).ReadObject());

        var decryptEngine = new Pkcs1Encoding(new RsaEngine());
        decryptEngine.Init(false, priKey);

        var decrypted = decryptEngine.ProcessBlock(data, 0, data.Length);
        return decrypted;
    }

    private static byte[] CryptByRSA(byte[] data)
    {
        RsaPrivateCrtKeyParameters priKey;
        using (var reader = new StringReader(NewPrivateKey))
            priKey = ((RsaPrivateCrtKeyParameters)new PemReader(reader).ReadObject());

        // PKCS1Padding
        var encryptEngine = new Pkcs1Encoding(new RsaEngine());
        encryptEngine.Init(true, priKey);

        var cipher = encryptEngine.ProcessBlock(data, 0, data.Length);
        return cipher;
    }

    private static string DecryptByRSAFromBase64(string base64Data)
    {
        var r = DecryptByRSA(Convert.FromBase64String(base64Data));
        var content = Encoding.UTF8.GetString(r);
        return content;
    }

    private static string CryptByRSAToBase64(string data)
    {
        var r = CryptByRSA(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(r);
    }
}

public class LicenseRequest
{
    public String K;
    public String DI;
    public String P;

    public LicenseResponse toResponse(string N, string O)
    {
        
        LicenseResponse response = new()
        {
            K = K,
            DI = DI,
            P = P,
            N = N,
            O = O
        };

        return response;
    }
}

public class LicenseResponse
{
    public String K;
    public String N = "Cherry";
    public String O = "cherry.org";
    public String DI;
    public String P;
    public long T = 2298472123;
}