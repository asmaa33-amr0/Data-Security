using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        DES des = new DES();
        public string Decrypt(string cipherText, List<string> key)
        {
            string res1 = des.Decrypt(cipherText, key[0]);
            string res2 = des.Encrypt(res1, key[1]);
            return des.Decrypt(res2, key[0]);
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string res1 = des.Encrypt(plainText, key[0]);
            string res2 = des.Decrypt(res1, key[1]);
            return des.Encrypt(res2, key[0]);
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
