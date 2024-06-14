using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }




        public string Decrypt(string ciphertext, string key1)
        {
            string key = ReplaceJWithI(key1);

            string result1 = "";

            ciphertext = new string(ciphertext.Where(char.IsLetter).ToArray()).ToLower();
            string uniqueKey = RemoveDuplicates(key);
            ciphertext = ReplaceJWithI(ciphertext);

            char[,] matrix = new char[5, 5];
            int keyIndex = 0;

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (keyIndex < uniqueKey.Length)
                    {
                        matrix[row, col] = uniqueKey[keyIndex];
                        keyIndex++;
                    }
                }
            }

            char currentChar = 'a';

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (matrix[row, col] == '\0')
                    {
                        while (uniqueKey.Contains(currentChar.ToString()) || currentChar == 'j')
                        {
                            currentChar++;
                        }

                        matrix[row, col] = currentChar;
                        currentChar++;
                    }
                }
            }





            for (int i = 0; i < ciphertext.Length; i += 2)
            {
                char f = ciphertext[i];
                char s = ciphertext[i + 1];


                int row1 = 4, col1 = 4, row2 = 4, col2 = 4;


                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (f == matrix[row, col])
                        {
                            row1 = row;
                            col1 = col;
                        }
                        if (s == matrix[row, col])
                        {
                            row2 = row;
                            col2 = col;
                        }
                    }
                }

                if (row1 == row2)
                {
                    result1 += matrix[row1, (col1 + 4) % 5];
                    result1 += matrix[row2, (col2 + 4) % 5];
                }
                else if (col1 == col2)
                {
                    result1 += matrix[(row1 + 4) % 5, col1];
                    result1 += matrix[(row2 + 4) % 5, col2];
                }
                else
                {
                    result1 += matrix[row1, col2];
                    result1 += matrix[row2, col1];
                }
            }
            string finalRes = result1;
            if (result1[result1.Length - 1] == 'x')
            {
                finalRes = finalRes.Remove(result1.Length - 1);
            }

            int k = 0;
            for (int i = 0; i < finalRes.Length; i++)
            {
                if (result1[i] == 'x')
                {
                    if (result1[i - 1] == result1[i + 1])
                    {
                        if (i + k < finalRes.Length && (i - 1) % 2 == 0)
                        {
                            finalRes = finalRes.Remove(i + k, 1);
                            k--;
                        }
                    }
                }
            }

            return finalRes;


        }



        public string RemoveDuplicates(string input)
        {
            string result = "";
            foreach (char c in input)
            {
                if (!result.Contains(c))
                {
                    result += c;
                }
            }
            return result;
        }

        public string ReplaceJWithI(string input)
        {
            string result = "";

            foreach (char c in input)
            {
                if (c == 'j')
                {
                    result += 'i';
                }
                else
                {
                    result += c;
                }
            }

            return result;
        }

        public string Encrypt(string plainText, string key1)
        {

            string key = ReplaceJWithI(key1);

            string result1 = "";

            string uniqueKey = RemoveDuplicates(key);
            char[,] matrix = new char[5, 5];
            int keyIndex = 0;

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (keyIndex < uniqueKey.Length)
                    {
                        matrix[row, col] = uniqueKey[keyIndex];
                        keyIndex++;
                    }
                }
            }

            char currentChar = 'a';

            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    if (matrix[row, col] == '\0')
                    {
                        while (uniqueKey.Contains(currentChar.ToString()) || currentChar == 'j')
                        {
                            currentChar++;
                        }

                        matrix[row, col] = currentChar;
                        currentChar++;
                    }
                }
            }


            for (int i = 0; i < plainText.Length - 1; i += 2)
            {
                if (plainText[i] == plainText[i + 1])
                {
                    plainText = plainText.Insert(i + 1, "x");
                }
            }


            string plain_final = ReplaceJWithI(plainText);
            if (plain_final.Length % 2 != 0)
                plain_final += 'x';
            for (int i = 0; i < plain_final.Length; i += 2)
            {
                char f = plain_final[i];
                char s = plain_final[i + 1];






                int row1 = 0, col1 = 0, row2 = 0, col2 = 0;

                for (int row = 0; row < 5; row++)
                {
                    for (int col = 0; col < 5; col++)
                    {
                        if (f == matrix[row, col])
                        {
                            row1 = row;
                            col1 = col;
                        }
                        if (s == matrix[row, col])
                        {
                            row2 = row;
                            col2 = col;
                        }
                    }
                }

                if (row1 == row2)
                {
                    result1 += matrix[row1, (col1 + 1) % 5];
                    result1 += matrix[row2, (col2 + 1) % 5];
                }
                else if (col1 == col2)
                {
                    result1 += matrix[(row1 + 1) % 5, col1];
                    result1 += matrix[(row2 + 1) % 5, col2];
                }
                else
                {
                    result1 += matrix[row1, col2];
                    result1 += matrix[row2, col1];
                }
            }


            return result1;
        }


    }
}

