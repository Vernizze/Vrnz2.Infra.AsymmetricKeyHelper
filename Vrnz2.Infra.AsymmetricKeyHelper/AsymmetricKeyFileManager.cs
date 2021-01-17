using System.IO;
using Vrnz2.Infra.CrossCutting.Utils;

namespace Vrnz2.Infra.AsymmetricKeyHelper
{
    internal class AsymmetricKeyFileManager
    {
        #region Variables

        private static AsymmetricKeyFileManager _instance = null;

        private string _private_key = string.Empty;
        private string _public_key = string.Empty;

        #endregion

        #region Constructors

        private AsymmetricKeyFileManager()
        {
            _private_key = GetPrivateKey();
            _public_key = GetPublicKey();
        }

        #endregion

        #region Attributes

        public static AsymmetricKeyFileManager GetInstance
        {
            get
            {
                _instance = _instance ?? new AsymmetricKeyFileManager();

                return _instance;
            }
        }

        public string PrivateKey
            => _private_key;

        public string PublicKey
            => _public_key;

        #endregion

        #region Methods

        private string GetPrivateKey()
            => FilesAndFolders.GetFileContent(Path.Combine(FilesAndFolders.AppPath(), $"_sec", "private_key.txt"));

        private string GetPublicKey()
            => FilesAndFolders.GetFileContent(Path.Combine(FilesAndFolders.AppPath(), $"_sec", "public_key.txt"));

        #endregion
    }
}
