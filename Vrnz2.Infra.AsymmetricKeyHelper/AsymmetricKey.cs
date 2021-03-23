using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Vrnz2.Infra.AsymmetricKeyHelper
{
    public class AsymmetricKey
           : IDisposable
    {
        #region Variables

        private UTF8Encoding _encoder = new UTF8Encoding();

        private readonly X509Certificate2 _certificate;

        #endregion

        #region Constructors

        public AsymmetricKey(string filePath, string pwd)
        {
            if (!File.Exists(filePath)) return;

            _certificate = new X509Certificate2(ReadFile(filePath), pwd);
        }

        #endregion

        #region Attributes

        public string PrivateKey { get; }
        public string PublicKey { get; }

        #endregion

        #region Methods

        public void Dispose()
            => _encoder = null;

        private byte[] ReadFile(string fileName)
        {
            byte[] data;

            using (FileStream f = new FileStream(fileName, FileMode.Open, FileAccess.Read)) 
            {
                int size = (int)f.Length;
                data = new byte[size];
                size = f.Read(data, 0, size);
                f.Close();
            }

            return data;
        }

        public string Encrypt(string data)
        {
            var sb = new StringBuilder();
            byte[] encryptedByteArray = null;
            var item = 0;

            var dataToEncrypt = this._encoder.GetBytes(data);

            using (RSA rsa = _certificate.GetRSAPublicKey())
                encryptedByteArray = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA1);

            var length = encryptedByteArray.Count();

            foreach (var x in encryptedByteArray)
            {
                item++;
                sb.Append(x);

                if (item < length)
                    sb.Append(",");
            }

            return sb.ToString();
        }

        public string Decrypt(string data)
        {
            byte[] decryptedByte = null;

            var dataArray = data.Split(new char[] { ',' });

            byte[] dataByte = new byte[dataArray.Length];

            for (int i = 0; i < dataArray.Length; i++)
                dataByte[i] = Convert.ToByte(dataArray[i]);

            using (RSA rsa = _certificate.GetRSAPrivateKey())
                decryptedByte = rsa.Decrypt(dataByte, RSAEncryptionPadding.OaepSHA1);

            return _encoder.GetString(decryptedByte);
        }

        #endregion
    }
}
