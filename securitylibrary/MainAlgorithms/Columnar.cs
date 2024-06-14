using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int count;
            List<int> keys = new List<int>();
            for(count = 2 ; count <= plainText.Length; count++)
            {
                int length = (int)Math.Ceiling((float)cipherText.Length/count);
                string cipher = "";
                for(int i = 0; i < length; i++)
                {
                    if(i*count > plainText.Length)
                        cipher += "x";
                    else
                        cipher += plainText[i*count];
                }
                bool isFound = cipherText.Contains(cipher);
                if (!isFound)
                    continue;

                
                for(int j = 0; j < count; j++)
                {
                    string cipher2 = "";
                    for (int i = 0; i < length; i++)
                    {
                        int index = j + i*count;
                        if (index >= plainText.Length)
                            cipher2 += "";
                        else
                            cipher2 += plainText[index];
                    }
                    int indexOfKey = cipherText.IndexOf(cipher2);
                    keys.Add(indexOfKey/length + 1);
                }
                break;
            }
            return keys;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int cipherLength = cipherText.Length;
            int columnLength = (int)Math.Ceiling((float)cipherLength / key.Count);
            Dictionary<int, string> columner = new Dictionary<int, string>();
            string plainText = "";
            for (int i = 0; i < columnLength; i++)
            {
                string temp = "";
                for (int j = 0; j < key.Count; j++)
                {
                    int index = (key[j] - 1) * columnLength + i;
                    if (index >= cipherLength)
                        temp += "x";
                    else
                        temp += cipherText[index];
                }
                columner[i] = temp;
            }
            for (int i = 0; i < columnLength; i++)
            {
                plainText += columner[i];
            }
            return plainText.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int plainLength = plainText.Length;
            int columnLength = (int)Math.Ceiling((float)plainLength / key.Count);
            Dictionary<int, string> columner = new Dictionary<int, string>();
            string cipherText = "";
            for (int i = 0; i < key.Count; i++)
            {
                int index = i;
                string temp = "";
                for (int j = 0; j < columnLength; j++)
                {
                    if (index >= plainLength)
                        temp += "x";
                    else
                        temp += plainText[index];

                    index += key.Count;
                }
                columner[key[i]] = temp;
            }
            for(int i = 1; i <= key.Count; i++)
            {
                cipherText += columner[i];
            }
            return cipherText;
        }
    }
}
