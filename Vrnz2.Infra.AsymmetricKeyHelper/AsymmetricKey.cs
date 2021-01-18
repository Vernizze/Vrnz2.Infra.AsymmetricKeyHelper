using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Vrnz2.Infra.AsymmetricKeyHelper.Extensions;

namespace Vrnz2.Infra.AsymmetricKeyHelper
{
    public class AsymmetricKey
           : IDisposable
    {
        #region Variables

        private UTF8Encoding _encoder = new UTF8Encoding();

        #endregion

        #region Constructors

        public AsymmetricKey()
        {
            PrivateKey = AsymmetricKeyFileManager.GetInstance.PrivateKey;
            PublicKey = AsymmetricKeyFileManager.GetInstance.PublicKey;
        }

        #endregion

        #region Attributes

        public string PrivateKey { get; }
        public string PublicKey { get; }

        #endregion

        #region Methods

        public void Dispose()
            => _encoder = null;

        public RSACryptoServiceProvider GetRSACryptoServiceProvider()
            => new RSACryptoServiceProvider();

        public string GeneratePublicKey()
        {
            var result = string.Empty;

            using (var rsa = GetRSACryptoServiceProvider())
                result = rsa.ToXmlString(false);

            return result;
        }

        public string GeneratePrivateKey()
        {
            var result = string.Empty;

            using (var rsa = GetRSACryptoServiceProvider())
                result = rsa.ToXmlString(true);

            return result;
        }

        public string Encrypt(string data)
        {
            var sb = new StringBuilder();
            byte[] encryptedByteArray = null;
            var item = 0;

            var dataToEncrypt = this._encoder.GetBytes(data);

            using (var rsa = GetRSACryptoServiceProvider())
            {
                rsa.FromXmlString2(PublicKey);

                encryptedByteArray = rsa.Encrypt(dataToEncrypt, false).ToArray();
            }

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
            {
                dataByte[i] = Convert.ToByte(dataArray[i]);
            }

            using (var rsa = GetRSACryptoServiceProvider())
            {
                rsa.FromXmlString2(PrivateKey);
                decryptedByte = rsa.Decrypt(dataByte, false);
            }

            return _encoder.GetString(decryptedByte);
        }

        #endregion
    }
}
