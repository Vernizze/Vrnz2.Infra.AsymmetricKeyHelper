using System;
using Xunit;

namespace Vrnz2.Infra.AsymmetricKeyHelper.Test
{
    public class CryptoTest
    {
        [Theory]
        [InlineData("Value01")]
        public void EncryptDecrypt_Success(string valueToEncrypt)
        {
            var decrypt_value = string.Empty;

            using (var asym_key = new AsymmetricKey()) 
            {
                var encrypt_value = asym_key.Encrypt(valueToEncrypt);

                decrypt_value = asym_key.Decrypt(encrypt_value);
            }

            Assert.Equal(valueToEncrypt, decrypt_value);
        }
    }
}
