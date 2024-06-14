using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            int index = 0;
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            char[,] table = make_table();
            foreach (char c in cipherText)
            {
                if (char.IsLetter(c))
                {

                    int shift = plainText[index] - 'A';

                    int col = plainText[index] - 'A';

                    int row = 0;
                    for (int i = 0; i < 26; i++)
                    {
                        if (table[i, col] == c)
                        {
                            row = i;
                            break;
                        }
                    }

                    key += (char)('A' + row);
                    index++;


                }

            }
            string keyout = "";
            keyout = string.Concat(key[0], key[1]);
            Console.WriteLine(key);
            string split = string.Concat(key[0], key[1]);
            for (int i = 2; i < key.Length; i++)
            {
                if (string.Concat(key[i], key[i + 1]) != split)
                {
                    keyout = string.Concat(keyout, key[i]);
                }
                else
                {
                    break;
                }
            }

            return keyout;
        }


        public string Decrypt(string cipherText, string key)
        {
            string deText = "";
            int keyin = 0;
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            char[,] tableau = make_table();
            foreach (char c in cipherText)
            {
                if (char.IsLetter(c))
                {
                    int shift = key[keyin] - 'A';
                    int col = key[keyin] - 'A';
                    int row = 0;
                    for (int i = 0; i < 26; i++)
                    {
                        if (tableau[i, col] == c)
                        {
                            row = i;
                            break;
                        }
                    }
                    deText += (char)('A' + row);
                    keyin++;
                    if (keyin == key.Length)
                    {
                        keyin = 0;
                    }
                }

            }

            return deText;
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] table = make_table();
            string enText = "";
            int keyin = 0;
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            foreach (char c in plainText)
            {
                if (char.IsLetter(c))
                {
                    int shift = key[keyin] - 'A';
                    int row = c - 'A';
                    int col = key[keyin] - 'A';
                    enText += table[row, col];
                    keyin++;
                    if (keyin == key.Length)
                    {
                        keyin = 0;
                    }

                }

            }
            return enText;

        }
        static char[,] make_table()
        {
            string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            char[,] table = new char[26, 26];
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    int shift = (i + j) % 26;
                    table[i, j] = letters[shift];
                }
            }
            return table;
        }


    }
}