using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plain, string cipher)

        {


            string key = "";
            string uniq = "";

            char[] key_arr = new char[26];
            char[] cipher_arr = new char[plain.Length];
            char[] plain_arr = new char[plain.Length];
            for (int i = 0; i < plain.Length; i++)
            {
                plain_arr[i] = plain[i];

            }
            for (int i = 0; i < cipher.Length; i++)
            {
                cipher_arr[i] = cipher[i];

            }
            for (int i = 0; i < key_arr.Length; i++)
            {
                key_arr[i] = '#';
            }

            char[] alpha = new char[26];
            char let = 'a';
            for (int i = 0; i < 26; i++)
            {
                alpha[i] = let;
                let++;

            }
            for (int k = 0; k < plain.Length; k++)
            {
                for (int i = 0; i < 26; i++)
                {
                    if (plain[k] == alpha[i])
                    {
                        key_arr[i] = cipher[k];
                        uniq += cipher[k];
                    }
                }
            }



            char letter = '!';
            for (int i = 0; i < key_arr.Length; i++)
            {

                if (key_arr[i] == '#')
                {
                    while (uniq.Contains(letter.ToString()))
                    {

                        letter++;
                    }
                    key_arr[i] = letter;
                    letter++;
                }
            }
            for (int i = 0; i < key_arr.Length; i++)
            {
                key += key_arr[i];
            }

            return key.ToLower();

        }

        public string Decrypt(string cipherText, string key)
        {

            Dictionary<char, char> map_cipher_alpha = new Dictionary<char, char>();


            for (int i = 0; i < key.Length; i++)
            {
                char keyChar = char.ToUpper(key[i]);
                char alphabetChar = (char)('a' + i);


                map_cipher_alpha.Add(keyChar, alphabetChar);
            }

            string plainText = "";


            foreach (char cipherChar in cipherText)
            {
                char uppercaseCipherChar = cipherChar;


                if (map_cipher_alpha.ContainsKey(uppercaseCipherChar))
                {
                    char decryptedChar = map_cipher_alpha[uppercaseCipherChar];


                    plainText += decryptedChar;

                }

            }

            return plainText;
        }

        public string Encrypt(string plain, string key)
        {
            char currentChar = 'a';
            char[] key_arr = new char[27];
            for (int i = 0; i < key.Length; i++)
            {
                key_arr[i] = key[i];

            }
            for (int j = key.Length; j < 26; j++)
            {


                while (key.Contains(currentChar.ToString()))
                {
                    currentChar++;
                }
                key_arr[j] = currentChar;
            }
            string cipher = "";
            char[] alpha = new char[26];
            char let = 'a';
            for (int i = 0; i < 26; i++)
            {
                alpha[i] = let;
                let++;

            }
            for (int k = 0; k < plain.Length; k++)
            {
                for (int i = 0; i < 26; i++)
                {
                    if (plain[k] == alpha[i])
                    {
                        cipher += key_arr[i];
                    }
                }
            }

            return cipher;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {


            string plaintext = null;
            char[] alpha_list = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };
            char[] ciphertext = cipher.ToLower().ToCharArray();

            char[] cipher_list = new char[26];
            var charCounts = cipher
                            .GroupBy(q => q)
                            .ToDictionary(g => g.Key, g => g.Count())

                        .OrderByDescending(kv => kv.Value);

            int c = 0;
            foreach (var kvp in charCounts)
            {


                float temp = kvp.Value;
                cipher_list[c] = kvp.Key;
                c++;


            }





            for (int i = 0; i < ciphertext.Length; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if (ciphertext[i] == cipher_list[j] + 32)
                    {
                        ciphertext[i] = alpha_list[j];
                        break;
                    }
                }
            }

            for (int i = 0; i < ciphertext.Length; i++)
            {
                plaintext += ciphertext[i];
            }
            return plaintext;
        }
    }
}
