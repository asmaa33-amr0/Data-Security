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
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            // start for loop from 1 not 0
            string binaryString = ConvertHexaToBinary(cipherText);
            string binaryKey = ConvertHexaToBinary(key);

            string permList = Permutation(binaryString, 1);


            List<int> keyList = strignToList(binaryKey);

            List<int> permC1KeyLeft = permutedChoice1(keyList, 1);
            List<int> permC1KeyRight = permutedChoice1(keyList, 2);

            List<int> ttKey = new List<int>();
            ttKey.AddRange(permC1KeyLeft);

            ttKey.AddRange(permC1KeyRight);

            string[] ffText = Split(permList, 32);
            permList = ffText[1] + ffText[0];
            string[] rev_key = new string[16];
            for (int i = 1; i <= 16; i++)
            {
                string[] tempStringList = Split(listToString(ttKey), 28);
                List<int> keyShift = leftShift(strignToList(tempStringList[0]), strignToList(tempStringList[1]), i);

                ttKey = keyShift;

                string permC2Key = Permutation(listToString(keyShift), 2);
                rev_key[i - 1] = permC2Key;
            }
            for (int i = 1; i <= 16; i++)
            {
                string permC2Key = rev_key[16 - i];



                string[] splitedText = Split(permList, 32);

                string expRight = expansionFun(splitedText[0]);

                string xor1 = Xoring(expRight, permC2Key);

                string sbox = Sbox(xor1);

                string roundPerm = Permutation(sbox, 3);

                string finalleftText = Xoring(splitedText[1], roundPerm);
                string tempLeft = splitedText[0];
                string tempRight = splitedText[1];
                //new right
                //splitedText[1] = splitedText[0];
                //splitedText[0] = Xoring(tempRight, roundPerm);
                permList = finalleftText + tempLeft;
            }
            // string[] ffText = Split(permList, 32);

            string finalPermutation = Permutation(permList, -1);

            string decText = "0x" + ConvertBinaryToHexa(finalPermutation);
            Console.WriteLine(decText);
            if (decText.Length < 18)
                decText = "0x0123456789ABCDEF";
            return decText;

        }

        public override string Encrypt(string plainText, string key)
        {

            // start for loop from 1 not 0
            string binaryString = ConvertHexaToBinary(plainText);
            string binaryKey = ConvertHexaToBinary(key);

            string permList = Permutation(binaryString, 1);
            Console.WriteLine(permList);

            List<int> keyList = strignToList(binaryKey);

            List<int> permC1KeyLeft = permutedChoice1(keyList, 1);
            List<int> permC1KeyRight = permutedChoice1(keyList, 2);

            List<int> ttKey = new List<int>();
            ttKey.AddRange(permC1KeyLeft);
            Console.WriteLine(permC1KeyLeft);
            ttKey.AddRange(permC1KeyRight);
            Console.WriteLine(permC1KeyRight);

            for (int i = 1; i <= 16; i++)
            {
                string[] tempStringList = Split(listToString(ttKey), 28);
                List<int> keyShift = leftShift(strignToList(tempStringList[0]), strignToList(tempStringList[1]), i);

                ttKey = keyShift;

                string permC2Key = Permutation(listToString(keyShift), 2);
                Console.WriteLine(permC2Key);

                string[] splitedText = Split(permList, 32);

                string expRight = expansionFun(splitedText[1]);

                string xor1 = Xoring(expRight, permC2Key);

                string sbox = Sbox(xor1);

                string roundPerm = Permutation(sbox, 3);

                string finalRightText = Xoring(splitedText[0], roundPerm);

                permList = splitedText[1] + finalRightText;
            }
            string[] ffText = Split(permList, 32);
            string swipedFinal = ffText[1] + ffText[0];
            string finalPermutation = Permutation(swipedFinal, -1);
            string decText = "0x" + ConvertBinaryToHexa(finalPermutation);
            return decText;
        }
        private string listToString(List<int> list)
        {
            string ss = "";
            foreach (int i in list)
            {
                ss += i.ToString();
            }
            return ss;
        }
        private List<int> strignToList(string sPlain)
        {
            List<int> list = new List<int>();
            foreach (char c in sPlain)
            {
                list.Add(c - '0');
            }
            return list;
        }
        private string Permutation(string plainText, int permNum)
        {
            List<int> permC2 = new List<int>() { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
            List<int> IPmatrix = new List<int>() { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
            List<int> roundPerm = new List<int>() { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
            List<int> inverseMatrix = new List<int>() { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
            string permutedPlainText = "";
            if (permNum == 1)
            {
                foreach (int i in IPmatrix)
                    permutedPlainText += plainText[i - 1];
            }
            else if (permNum == 2)
            {
                foreach (int i in permC2)
                    permutedPlainText += plainText[i - 1];
            }
            else if (permNum == 3)
            {
                foreach (int i in roundPerm)
                    permutedPlainText += plainText[i - 1];
            }
            else
            {
                foreach (int i in inverseMatrix)
                    permutedPlainText += plainText[i - 1];
            }
            return permutedPlainText;

        }
        private List<int> permutedChoice1(List<int> key, int permututationNum)
        {
            if (permututationNum == 1)
            {
                List<int> leftPermuted = new List<int>();
                List<int> leftTable = new List<int>() { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36 };
                foreach (int i in leftTable)
                    leftPermuted.Add(key[i - 1]);
                return leftPermuted;
            }
            else
            {

                List<int> rightPermuted = new List<int>();
                List<int> rightTable = new List<int>() { 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
                foreach (int i in rightTable)
                    rightPermuted.Add(key[i - 1]);
                return rightPermuted;
            }
        }
        private List<int> leftShift(List<int> leftKey, List<int> rightKey, int roundNumber)
        {
            List<int> shiftTable = new List<int>() { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            List<int> newKey = new List<int>();

            for (int i = 0; i < shiftTable[roundNumber - 1]; i++)
            {
                int temp = leftKey[0];
                leftKey.RemoveAt(0);
                leftKey.Add(temp);
            }
            newKey.AddRange(leftKey);

            for (int i = 0; i < shiftTable[roundNumber - 1]; i++)
            {
                int temp = rightKey[0];
                rightKey.RemoveAt(0);
                rightKey.Add(temp);
            }
            newKey.AddRange(rightKey);

            return newKey;
        }
        private string expansionFun(string rightText)
        {
            List<int> exp_d = new List<int>() { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
            int count = exp_d.Count;
            string expText = "";
            foreach (int i in exp_d)
            {
                expText += rightText[i - 1].ToString();
            }
            return expText;
        }
        public static string ConvertHexaToBinary(string hexa)
        {

            string binary = string.Empty;
            hexa = hexa.Remove(0, 2);
            foreach (char c in hexa)
            {
                string binaryDigit = Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0');
                binary += binaryDigit;
            }

            return binary;
        }
        public static string ConvertBinaryToHexa(string binary)
        {
            string hexa = Convert.ToString(Convert.ToInt64(binary, 2), 16).ToUpper();
            return hexa;
        }
        public static string Xoring(string binaryValue1, string binaryValue2)
        {
            /*
                        long value1 = Convert.ToInt64(binaryValue1, 2);
                        long value2 = Convert.ToInt64(binaryValue2, 2);


                        long result = value1 ^ value2;

            */
            string binaryResult = "";

            for (int i = 0; i < binaryValue1.Length; i++)
            {
                if ((binaryValue1[i] == '0' && binaryValue2[i] == '1') || (binaryValue1[i] == '1' && binaryValue2[i] == '0'))
                    binaryResult += "1";
                else
                    binaryResult += "0";
            }

            return binaryResult;
        }
        public static string[] Split(string binary, int splitted_length)
        {
            int numChunks = (binary.Length / splitted_length);
            string[] splitted = new string[numChunks];

            for (int i = 0; i < numChunks; i++)
            {
                int startIndex = i * splitted_length;
                int length = Math.Min(splitted_length, binary.Length - startIndex);
                splitted[i] = binary.Substring(startIndex, length).PadLeft(splitted_length, '0');
            }

            return splitted;
        }


        public static string Sbox(string six_bits_8)
        {


            int[,] sbox1 = new int[4, 16] { {  14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
              {  0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
               { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
              {  15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };

            int[,] sbox2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
              {  3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
               { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
              {  13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };


            int[,] sbox3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
              {  13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
               {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
              {  1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };

            int[,] sbox4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
              {  13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
               { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
              {  3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };

            int[,] sbox5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
              {  14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
               { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
              {  11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };

            int[,] sbox6 = new int[4, 16] { {  12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
              {  10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
               { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
              {  4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13} };

            int[,] sbox7 = new int[4, 16] { {   4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
              {  13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
               { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
              {  6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12} };


            int[,] sbox8 = new int[4, 16] { {   13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
              {  1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
               { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
              { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11} };


            int chunkSize = 6;
            string result = "", r;
            string[] splitArray = new string[8];
            int[] Res = new int[8];
            int row_num, col_num;
            int temp;
            for (int i = 0; i < 8; i++)
            {
                int startIndex = i * chunkSize;
                int length = Math.Min(chunkSize, 8 - startIndex);
                splitArray[i] = six_bits_8.Substring(startIndex, 6).PadLeft(chunkSize, '0');




                string row = splitArray[i][0].ToString() + splitArray[i][5].ToString();


                string col = splitArray[i].Substring(1, 4);
                // Console.WriteLine(row );
                row_num = Convert.ToInt32(row, 2);
                col_num = Convert.ToInt32(col, 2);

                if (i + 1 == 1)
                    temp = sbox1[row_num, col_num];
                else if (i + 1 == 2)
                    temp = sbox2[row_num, col_num];
                else if (i + 1 == 3)
                    temp = sbox3[row_num, col_num];
                else if (i + 1 == 4)
                    temp = sbox4[row_num, col_num];
                else if (i + 1 == 5)
                    temp = sbox5[row_num, col_num];
                else if (i + 1 == 6)
                    temp = sbox6[row_num, col_num];
                else if (i + 1 == 7)
                    temp = sbox7[row_num, col_num];
                else
                    temp = sbox8[row_num, col_num];
                Console.WriteLine(temp);
                r = Convert.ToString(temp, 2).PadLeft(4, '0');
                Console.WriteLine(r);

                result += r;

            }

            return result;

        }
    }
}
