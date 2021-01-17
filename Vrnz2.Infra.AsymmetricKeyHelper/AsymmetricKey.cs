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

        private string _private_key = string.Empty;
        private string _public_key = string.Empty;

        #endregion

        #region Constructors

        public AsymmetricKey()
        {
            this._private_key = AsymmetricKeyFileManager.GetInstance.PrivateKey;
            this._public_key = AsymmetricKeyFileManager.GetInstance.PublicKey;
        }

        #endregion

        #region Methods

        public void Dispose()
        {
            this._encoder = null;

            this._private_key = string.Empty;
            this._public_key = string.Empty;
        }

        public string GeneratePublicKey()
        {
            var result = string.Empty;

            using (var rsa = new RSACryptoServiceProvider())
                result = rsa.ToXmlString(false);

            return result;
        }

        public string GeneratePrivateKey()
        {
            var result = string.Empty;

            using (var rsa = new RSACryptoServiceProvider())
                result = rsa.ToXmlString(true);

            return result;
        }

        public string Encrypt(string data)
        {
            var sb = new StringBuilder();
            byte[] encryptedByteArray = null;
            var item = 0;

            var dataToEncrypt = this._encoder.GetBytes(data);

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString2(this._public_key);

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

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString2(this._private_key);
                decryptedByte = rsa.Decrypt(dataByte, false);
            }

            return _encoder.GetString(decryptedByte);
        }

        public string GetJwtSignature(string p_id, string u_id, string rnd)
        {
            byte[] plainText = UTF8Encoding.UTF8.GetBytes(string.Concat(p_id, u_id, rnd));
            byte[] signature = null;

            using (var rsaWrite = new RSACryptoServiceProvider())
            {
                rsaWrite.FromXmlString2(this._private_key);

                signature = rsaWrite.SignData(plainText, CryptoConfig.MapNameToOID("SHA1"));
            }

            return Convert.ToBase64String(signature);
        }

        public bool JwtSignatureIsValid(string p_id, string u_id, string rnd, string sign)
        {
            var hash = new SHA1Managed();
            var result = false;

            byte[] signature = Convert.FromBase64String(sign);
            byte[] original = UTF8Encoding.UTF8.GetBytes(string.Concat(p_id, u_id, rnd));
            byte[] hashedData;

            using (var rsaRead = new RSACryptoServiceProvider())
            {
                rsaRead.FromXmlString2(this._public_key);

                if (rsaRead.VerifyData(original, CryptoConfig.MapNameToOID("SHA1"), signature))
                {
                    hashedData = hash.ComputeHash(original);

                    result = rsaRead.VerifyHash(hashedData, CryptoConfig.MapNameToOID("SHA1"), signature);
                }
            }

            return result;
        }

        #endregion
    }
}
