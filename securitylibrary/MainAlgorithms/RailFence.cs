using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            String newCipherText;
            cipherText = cipherText.ToLower();
            for (int i = 2; i < plainText.Length; i++)
            {
                newCipherText = Encrypt(plainText, i);
                if(newCipherText == cipherText)
                    return i;
            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            int cipherLength = cipherText.Length;
            int rowLength = (int)Math.Ceiling((float)cipherLength / key);
            String plainText = "";
            for(int i = 0; i < rowLength; i++)
            {
                int index = i;
                for (int j = 0; j < key; j++)
                {
                    if (index >= cipherLength)
                        plainText += "";
                    else
                        plainText += cipherText[index];
                    
                    index += rowLength;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            int plainLength = plainText.Length;
            int rowLength = (int)Math.Ceiling((float)plainLength / key);
            String cipherText = "";
            for (int i = 0; i < key; i++)
            {
                int index = i;
                for(int j = 0; j < rowLength; j++)
                {
                    if (index >= plainLength)
                        cipherText += "";
                    else
                        cipherText += plainText[index];
                    
                    index+=key;
                }
            }
            return cipherText;
        }
    }
}
