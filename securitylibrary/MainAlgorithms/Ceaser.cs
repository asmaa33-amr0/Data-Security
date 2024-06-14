using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Schema;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {


            List<char> plainArr = plainText.ToList();
            List<char> alphabet = "abcdefghijklmnopqrstuvwxyz".ToList();
            List<int> indexs = new List<int>();
            List<char> cipher = new List<char>();
            for (int i = 0; i < plainArr.Count; i++)
            {
                for (int j = 0; j < alphabet.Count; j++)
                {
                    if (plainArr[i] == alphabet[j])
                    {
                        int v = (j + key) % 26;
                        indexs.Add(v);
                    }
                }
            }
            for (int i = 0; i < indexs.Count; i++)
            {
                Console.WriteLine(indexs[i]);
            }
            for (int i = 0; i < indexs.Count; i++)
            {
                Console.WriteLine(alphabet[indexs[i]]);
                char c = alphabet[indexs[i]];
                cipher.Add(c);
            }
            string cipherStr = new string(cipher.ToArray());
            Console.WriteLine(cipherStr);
            return cipherStr;
        }

        public string Decrypt(string cipherText, int key)
        {
            List<char> plainArr = cipherText.ToLower().ToList();
            List<char> alphabet = "abcdefghijklmnopqrstuvwxyz".ToList();
            List<int> indexs = new List<int>();
            List<char> cipher = new List<char>();
            for (int i = 0; i < plainArr.Count; i++)
            {
                for (int j = 0; j < alphabet.Count; j++)
                {

                    if (plainArr[i] == alphabet[j])
                    {

                        int v = ((j - key)) % 26;
                        if (v < 0)
                        {
                            v += 26;
                        }

                        indexs.Add(v);
                    }
                }
            }
            for (int i = 0; i < indexs.Count; i++)
            {
                Console.WriteLine(indexs[i]);
            }
            for (int i = 0; i < indexs.Count; i++)
            {
                Console.WriteLine(alphabet[indexs[i]]);
                char c = alphabet[indexs[i]];
                cipher.Add(c);
            }
            string cipherStr = new string(cipher.ToArray());
            Console.WriteLine(cipherStr);
            return cipherStr;
        }

        public int Analyse(string plainText, string cipherText)
        {
            List<char> plainArr = plainText.ToLower().ToList();
            List<char> alphabet = "abcdefghijklmnopqrstuvwxyz".ToList();
            List<int> indexs = new List<int>();
            char[] cipherArr = cipherText.ToLower().ToCharArray();
            int key = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                int first = -1;
                int sec = -1;
                for (int j = 0; j < alphabet.Count; j++)
                {
                    if (cipherArr[i] == alphabet[j])
                    {
                        first = j;
                    }
                    if (plainText[i] == alphabet[j])
                    {
                        sec = j;
                    }
                    if (first >= 0 && sec >= 0)
                    {
                        key = first - sec;
                        if (key < 0) { key += 26; }
                    }

                }
            }
            Console.WriteLine(key);
            return key;
        }
    }
}