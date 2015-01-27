using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace LynxEmailMsgLib.Crypto
{
    // this class is used to get an AES key and iv for use in the attachment encryption and is done
    //      this way so that the key and iv can be encrypted separately and included in the attachment
    public class SymmetricKey
    {
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }

        const int MAXKEYSIZE = 256;
        const int MEDKEYSIZE = 192;
        const int MINKEYSIZE = 128;

        public SymmetricKey()
        {
            using (AesManaged aes = new AesManaged { KeySize = MAXKEYSIZE }) {
                Key = aes.Key;
                IV = aes.IV;
            }
        }
    }
}
