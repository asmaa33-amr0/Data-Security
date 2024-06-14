using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
   
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string maincipher, string mainkey)
        {
            string[,] Keymatrix = change_string_in_matrix(mainkey);
            string[,] myCiphermatrix = change_string_in_matrix(maincipher);
            int length = 10;
            string[,] keyMatrix10 = key(10, Keymatrix);
            string[,] roundedMatrix10 = generateRoundKey(myCiphermatrix, keyMatrix10);
            string[,] shifted_matrix = inverse_shift_row(roundedMatrix10);
            string[,] substitute = inverse_sub(shifted_matrix);
            string[,] str = new string[4, 4];
            string[,] sub = new string[4, 4];
            string[,] keyM = new string[4, 4];
            string[,] round = new string[4, 4];
            string[,] imc = new string[4, 4];
            for (length = 9; length > 0; length--)
            {
                keyM = key(length, Keymatrix);
                round = generateRoundKey(substitute, keyM);
                imc = inverse_mix_column(round);
                str = inverse_shift_row(imc);
                sub = inverse_sub(str);
                substitute = sub;
            }
            string[,] sr = new string[4, 4];
            string[,] subb = new string[4, 4];
            string[,] rmm = new string[4, 4];
            string[,] k = new string[4, 4];
            sr = inverse_shift_row(imc);
            subb = inverse_sub(sr);
            k = key(length, Keymatrix);
            rmm = generateRoundKey(subb, k);
            List<string> plain_array = new List<string>();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain_array.Add(rmm[j, i]);
                }
            }
            string plaintext = "";
            plaintext = "0x" + string.Join("", plain_array);

            return plaintext;
            throw new NotImplementedException();
        }


        byte[,] SBox = new byte[16, 16] { {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
{0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
{0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
{0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
{0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
{0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
{0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
{0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
{0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
{0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
{0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
{0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
{0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
{0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
{0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
{0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} };

        byte[,] Rcon = new byte[4, 10] { {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};




        byte[,] key_expansion = new byte[44, 4];
        byte[] Rotword(byte[] word)
        {
            byte first = word[0];
            int i = 0;
            while (i < 3)
            {
                word[i] = word[i + 1];
                i++;
            }
            word[3] = first;
            return word;
        }
        byte[] Sub_Byte(byte[] word)
        {
            byte[] col = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string str = Convert.ToString(word[i], 16);
                int digit1, digit2;
                if (str.Length != 1)
                {
                    digit1 = Convert.ToInt32(str[0].ToString(), 16);
                    digit2 = Convert.ToInt32(str[1].ToString(), 16);
                }
                else
                {
                    digit1 = 0;
                    digit2 = Convert.ToInt32(str[0].ToString(), 16);
                }
                col[i] = SBox[digit1, digit2];
            }
            return col;
        }

        byte[] xor(byte[] first, byte[] second, byte[] third, int first_col_check)
        {
            byte[] col = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string str = "";
                if (first_col_check != 0)
                {
                    str = Convert.ToString(first[i] ^ second[i] ^ third[i], 16);
                }
                else
                {
                    str = Convert.ToString(first[i] ^ second[i], 16);
                }
                col[i] = Convert.ToByte(str, 16);
            }
            return col;
        }


        byte[,] get_key_matrix(int index)
        {
            byte[,] mat = new byte[4, 4];
            int row = 0, col = 0;
            for (int i = index * 4; i < index * 4 + 4; i++)
            {
                col = 0;
                for (int j = 0; j < 4; j++)
                {
                    mat[col, row] = key_expansion[i, j];
                    col++;
                }
                row++;
            }
            return mat;
        }

        byte[,] RoundKey(byte[,] state, int Round_index)
        {
            byte[,] key_round;
            key_round = get_key_matrix(Round_index);
            string tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp = Convert.ToString(key_round[i, j] ^ state[i, j], 16);
                    key_round[i, j] = Convert.ToByte(tmp, 16);
                }
            }
            return key_round;
        }
        void implement_key_expansion()
        {
            int R_ind = 0;
            byte[] first = new byte[4];
            byte[] second = new byte[4];
            byte[] third = new byte[4];
            byte[] fourth = new byte[4];

            for (int i = 4; i < 44; i++)
            {
                for (int k = 0; k < 4; k++)
                {
                    first[k] = key_expansion[i - 1, k];
                    second[k] = key_expansion[i - 4, k];
                    if (R_ind < 10)
                        third[k] = Rcon[k, R_ind];
                }

                if (i % 4 == 0)
                {
                    R_ind++;
                    first = Rotword(first);
                    first = Sub_Byte(first);
                    fourth = xor(first, second, third, 1);
                }
                else
                {
                    fourth = xor(first, second, third, 0);
                }

                for (int j = 0; j < 4; j++)
                {
                    key_expansion[i, j] = fourth[j];
                }
            }
        }


        byte[,] mixCols(byte[,] shiftedmatrix)
        {
            byte[,] result_matrix = new byte[4, 4];
            for (byte i = 0; i < 4; i++)
            {
                for (byte j = 0; j < 4; j++)
                {
                    result_matrix[i, j] = FindRijndaelMixColumnsValue(i, j, shiftedmatrix);
                }
            }



            return result_matrix;
        }
        public byte FindRijndaelMixColumnsValue(byte row, byte col, byte[,] A)
        {
            byte result = 0;
            byte shiftedValue = 0;
            byte _1B = 0x1B;
            bool MSB_Set = false;
            byte[,] rijndaelMatrix = new byte[4, 4]
            {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2}
            };

            for (int i = 0; i < 4; i++)
            {
                MSB_Set = false;
                byte rijndaelValue = rijndaelMatrix[row, i];
                byte aValue = A[i, col];

                if (rijndaelValue == 1)
                {
                    result ^= aValue;
                }
                else if (rijndaelValue == 2 || rijndaelValue == 3)
                {
                    if ((aValue & (1 << 7)) != 0)
                        MSB_Set = true;

                    shiftedValue = (byte)(aValue << 1);
                    if (MSB_Set)
                    {
                        shiftedValue ^= _1B;
                    }
                    if (rijndaelValue == 3)
                    {
                        shiftedValue ^= aValue; 
                    }

                    result ^= shiftedValue;
                }
            }
            return result;
        }


        byte[,] initial_round(byte[,] state)
        {
            string str = "";
            int i = 0;
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    str = Convert.ToString(state[j, i] ^ key_expansion[i, j], 16);
                    state[j, i] = Convert.ToByte(str, 16);
                    j++;
                }
                i++;
            }
            return state;
        }
        byte[,] substituteMatrix(byte[,] word)
        {
            byte[,] mat = new byte[4, 4];
            int digit1 = 0, digit2 = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string str = Convert.ToString(word[i, j], 16);

                    if (str.Length != 1)
                    {



                        digit1 = Convert.ToInt32(str[0].ToString(), 16);
                        digit2 = Convert.ToInt32(str[1].ToString(), 16);
                    }
                    else if (str.Length == 1)
                    {
                        digit1 = 0;
                        digit2 = Convert.ToInt32(str[0].ToString(), 16);



                    }




                    mat[i, j] = SBox[digit1, digit2];
                }
            }
            return mat;
        }

        byte[,] shiftMatrix(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            byte[] row = new byte[4];
            int k = 0;





            while (k < 4)
            {
                for (int j = 0; j < 4; j++)
                {
                    row[j] = matrix[k, j];
                }

                UInt32 number = 0;
                for (int i = 0; i < 4; i++)
                {



                    number += Convert.ToUInt32(row[i]);
                    if (i != 3) number = number << 8;
                }
                number = ((number << (k * 8)) | (number) >> (32 - (k * 8)));



                byte[] newRow = new byte[4];
                for (int i = 3; i >= 0; i--)
                {
                    newRow[i] = (byte)(number & 0xFF);
                    number = number >> 8;
                }
                row = newRow;



                for (int j = 0; j < 4; j++)
                {
                    newMatrix[k, j] = row[j];
                }
                k++;
            }
            return newMatrix;
        }
        byte[,] xorMatrix(byte[,] matrix, byte[,] key)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j] ^ key[i, j], 16);
                    newMatrix[i, j] = Convert.ToByte(tmp, 16);
                }
            }
            return newMatrix;
        }
        byte[,] finalRound(byte[,] state)
        {
            state = substituteMatrix(state);

            state = shiftMatrix(state);

            state = RoundKey(state, 10);

            return state;
        }
        byte[,] main_rounds(byte[,] state, int round)
        {
            state = substituteMatrix(state);


            state = shiftMatrix(state);


            state = mixCols(state);

            state = RoundKey(state, round);

            return state;
        }
        byte advancedmultiplybyTwo(byte x)
        {
            byte ret;
            UInt32 temp = Convert.ToUInt32(x << 1);
            ret = (byte)(temp & 0xFF);
            if (x > 127)
                ret = Convert.ToByte(ret ^ 27);
            return ret;
        }
        public override string Encrypt(string plainText, string key)
        {

            byte[,] state = new byte[4, 4];
            int k = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string tmp = "0x" + plainText[k] + plainText[k + 1];
                    state[i, j] = Convert.ToByte(tmp, 16);
                    k += 2;
                }
            }
            byte[,] matrix_key = new byte[4, 4];
            int k1 = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string tmp = "0x" + key[k1] + key[k1 + 1];
                    matrix_key[j, i] = Convert.ToByte(tmp, 16);
                    k1 += 2;
                }
            }





            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    key_expansion[i, j] = matrix_key[i, j];

            implement_key_expansion();
            state = initial_round(state);



            for (int i = 1; i < 10; i++)
            {
                state = main_rounds(state, i);
            }



            state = finalRound(state);
            string encrypted_message = "0x";
            for (int i = 0; i < 4 * 4; i++)
            {
                encrypted_message += state[i % 4, i / 4].ToString("X2");
            }



            return encrypted_message;

        }

        public static string[] Sub_Box(string[] w)
        {
            byte[,] sbox = new byte[16, 16] {
                  //1  //2   //3   //4   //5   //6   //7   //8   //9   //10   //11  //12  //13  //14  //15  //16
                {0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76 },//1
                { 0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0 },//2
                { 0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15 },//3
                { 0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75 },//4
                { 0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84},//5
                { 0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf},//6
                { 0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8},//7
                { 0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2},//8
                { 0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73},//9
                { 0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb},//10
                { 0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79},//11
                { 0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08},//12
                { 0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a},//13
                { 0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e},//14
                { 0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf},//15
                { 0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16}//16
                    };
            string[] newst = new string[4];
            UInt32[] k = new UInt32[4];
            for (int i = 0; i < 4; i++)
            {

                k[i] = Convert.ToUInt32(w[i], 16);
            }

            for (int i = 0; i < 4; i++)
            {
                UInt32 n = (k[i] & 0xf0) >> 4;
                UInt32 j = k[i] & 0x0f;

                newst[i] = Convert.ToString(sbox[n, j], toBase: 16);
                if (newst[i].Length == 1)
                {
                    newst[i] = "0" + Convert.ToString(sbox[n, j], toBase: 16);
                }

            }
            return newst;

        }

        static string[,] generateRoundKey(string[,] plain, string[,] key)
        {
            string[,] Round_Matrix = new string[4, 4];
            UInt32[,] plain_Matrix = new UInt32[4, 4];
            UInt32[,] key_Matrix = new UInt32[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plain_Matrix[i, j] = Convert.ToUInt32(plain[i, j], 16);
                    key_Matrix[i, j] = Convert.ToUInt32(key[i, j], 16);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Round_Matrix[i, j] = Convert.ToString((plain_Matrix[i, j] ^ key_Matrix[i, j]), toBase: 16);
                    if (Round_Matrix[i, j].Length == 1)
                    {
                        Round_Matrix[i, j] = "0" + Convert.ToString((plain_Matrix[i, j] ^ key_Matrix[i, j]), toBase: 16);
                    }
                }
            }
            return Round_Matrix;
        }


        public static string[,] change_string_in_matrix(string text)
        {
            string[] y1 = new string[4];
            string[] y2 = new string[4];
            string[] y3 = new string[4];
            string[] y4 = new string[4];
            string[] ig = new string[16];
            string[,] matrix = new string[4, 4];
            UInt32[,] ma = new UInt32[4, 4];
            char[] charArr = text.ToCharArray();
            int l = 0;
            for (int i = 2; i < charArr.Length; i += 2)
            {
                ig[l] = string.Concat(charArr[i], charArr[i + 1]);

                l++;
            }

            for (int i = 0; i < 4; i++)
            {
                y1[i] = ig[i];
            }

            for (int i = 0; i < y2.Length; i++)
            {
                y2[i] = ig[i + 4];
            }

            for (int i = 0; i < y3.Length; i++)
            {
                y3[i] = ig[i + 8];
            }

            for (int i = 0; i < y4.Length; i++)
            {
                y4[i] = ig[i + 12];
            }

            for (int i = 0; i < 4; i++)
            {
                for (int n = 0; n < 4; n++)
                {
                    if (n == 0)
                    {
                        matrix[i, n] = y1[i];

                    }
                    else if (n == 1)
                    {
                        matrix[i, n] = y2[i];

                    }
                    else if (n == 2)
                    {
                        matrix[i, n] = y3[i];
                    }
                    else
                    {
                        matrix[i, n] = y4[i];
                    }
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    ma[i, j] = Convert.ToUInt32(matrix[i, j], 16);
                }
            }
            return matrix;

        }

        public static string[,] inverse_sub(string[,] text)
        {
            UInt32[,] utext = new UInt32[4, 4];

            for (int ii = 0; ii < 4; ii++)
            {
                for (int jj = 0; jj < 4; jj++)
                {
                    utext[ii, jj] = Convert.ToUInt32(text[ii, jj], 16);
                }
            }

            UInt32[,] inverse_sbox = new UInt32[16, 16]
            {
                  //1  //2   //3   //4   //5   //6   //7   //8   //9   //10   //11  //12  //13  //14  //15  //16
                {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB }, //0
                { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB }, //1
                { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E }, //2
                { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 }, //3
                { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 }, //4
                { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 }, //5
                { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 }, //6
                { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B }, //7
                { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 }, //8
                { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E  }, //9
                { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B }, //A
                { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 }, //B
                { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F }, //C
                { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF }, //D
                { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 }, //E
                { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }  //f
            };
            string[,] Retcol = new string[4, 4];
            UInt32 i, j, ri, ci;
            i = j = ri = ci = 0;
            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    ri = utext[i, j] >> 4;
                    ci = utext[i, j] & 0x0F;

                    Retcol[i, j] = Convert.ToString(inverse_sbox[ri, ci], toBase: 16);
                    if (Retcol[i, j].Length == 1)
                    {
                        Retcol[i, j] = "0" + Convert.ToString(inverse_sbox[ri, ci], toBase: 16);
                    }
                }
            }
            return Retcol;

        }

        public static string[,] inverse_shift_row(string[,] text)
        {
            UInt32[,] z = new UInt32[4, 4];
            string[,] sm = new string[4, 4];
            for (int ii = 0; ii < 4; ii++)
            {
                for (int jj = 0; jj < 4; jj++)
                {
                    z[ii, jj] = Convert.ToUInt32(text[ii, jj], 16);
                }
            }
            int i, j;
            UInt32 t, count;
            for (i = 1; i < 4; i++)
                for (count = 0; count < i; count++)
                {
                    t = z[i, 3];
                    for (j = 3; j > 0; j--)
                        z[i, j] = z[i, j - 1];
                    z[i, j] = t;
                }


            for (i = 0; i < 4; i++)
            {
                for (j = 0; j < 4; j++)
                {

                    sm[i, j] = Convert.ToString(z[i, j], toBase: 16);
                    if (sm[i, j].Length == 1)
                    {
                        sm[i, j] = "0" + Convert.ToString(z[i, j], toBase: 16);
                    }
                }
            }
            return sm;

        }

        public static UInt32 time(UInt32 x)
        {
            x = ((x << 1) ^ (((x >> 7) & 1) * 0x1b));

            return x;
        }

        public static UInt32 galiosmultiply(UInt32 x, UInt32 y)
        {
            UInt32 r;
            r = (((y & 1) * x) ^ ((y >> 1 & 1) * time(x)) ^ ((y >> 2 & 1) * time(time(x)))
                  ^ ((y >> 3 & 1) * time(time(time(x)))) ^ ((y >> 4 & 1) * time(time(time(time(x))))));

            return r;
        }

        public static string[,] inverse_mix_column(string[,] matrix)
        {
            UInt32[,] umatrix = new UInt32[4, 4];
            string[,] stringMAtrix = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                for (int n = 0; n < 4; n++)
                {
                    umatrix[i, n] = Convert.ToUInt32(matrix[i, n], 16);
                }
            }
            UInt32 a, b, c, d;
            for (int i = 0; i < 4; i++)
            {
                a = umatrix[0, i];
                b = umatrix[1, i];
                c = umatrix[2, i];
                d = umatrix[3, i];
                umatrix[0, i] = 0xFF & (galiosmultiply(a, 0x0e) ^ galiosmultiply(b, 0x0b) ^ galiosmultiply(c, 0x0d) ^ galiosmultiply(d, 0x09));
                umatrix[1, i] = 0xFF & (galiosmultiply(a, 0x09) ^ galiosmultiply(b, 0x0e) ^ galiosmultiply(c, 0x0b) ^ galiosmultiply(d, 0x0d));
                umatrix[2, i] = 0xFF & (galiosmultiply(a, 0x0d) ^ galiosmultiply(b, 0x09) ^ galiosmultiply(c, 0x0e) ^ galiosmultiply(d, 0x0b));
                umatrix[3, i] = 0xFF & (galiosmultiply(a, 0x0b) ^ galiosmultiply(b, 0x0d) ^ galiosmultiply(c, 0x09) ^ galiosmultiply(d, 0x0e));
            }
            for (int i = 0; i < 4; i++)
            {
                for (int n = 0; n < 4; n++)
                {
                    stringMAtrix[i, n] = Convert.ToString(umatrix[i, n], toBase: 16);
                    if (stringMAtrix[i, n].Length == 1)
                    {
                        stringMAtrix[i, n] = "0" + Convert.ToString(umatrix[i, n], toBase: 16);
                    }
                }
            }
            return stringMAtrix;
        }

        public static byte[,] generateRcon(int row)
        {
            byte[,] Rcon = new byte[10, 4] {
                                               {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00},{0x04, 0x00, 0x00, 0x00},{0x08, 0x00, 0x00, 0x00},
                                               {0x10, 0x00, 0x00, 0x00}, {0x20, 0x00, 0x00, 0x00},{0x40, 0x00, 0x00, 0x00}, {0x80, 0x00, 0x00, 0x00},
                                               {0x1b, 0x00, 0x00, 0x00},{0x36, 0x00, 0x00, 0x00} };

            byte[,] rcon = new byte[1, 4];
            for (int i = 0; i < 10; i++)
            {
                if (i == row)
                {
                    for (int h = 0; h < 4; h++)
                    {
                        rcon[0, h] = Rcon[i, h];
                    }
                    break;
                }
            }

            return rcon;
        }

        public static string[] XOORfun(string[] suba4, string[] a1, byte[,] Rcon)
        {
            string[] newArray = new string[4];
            UInt16[] a4 = new UInt16[4];
            UInt32[] a11 = new UInt32[4];

            int i = 0;
            while (i < 4)
            {
                a4[i] = Convert.ToUInt16(suba4[i], 16);
                i++;
            }

            i = 0;
            while (i < 4)
            {
                a11[i] = Convert.ToUInt16(a1[i], 16);
                i++;
            }

            i = 0;
            while (i < 4)
            {
                UInt32 ii = a11[i] ^ a4[i] ^ Rcon[0, i];
                newArray[i] = Convert.ToString(ii, toBase: 16);
                if (newArray[i].Length == 1)
                {
                    newArray[i] = "0" + newArray[i];
                }
                i++;
            }

            return newArray;
        }

        public static string[] XOR(string[] array1, string[] array2)
        {
            string[] Newarr = new string[4];
            UInt32[] a2 = new UInt32[4];

            for (int i = 0; i < 4; i++)
            {

                a2[i] = Convert.ToUInt32(array1[i], 16);

            }
            UInt32[] a1 = new UInt32[4];

            for (int i = 0; i < 4; i++)
            { a1[i] = Convert.ToUInt32(array2[i], 16); }
            for (int i = 0; i < 4; i++)
            {
                UInt32 ii = (a2[i] ^ a1[i]);
                Newarr[i] = Convert.ToString(ii, toBase: 16);
                if (Newarr[i].Length == 1)
                {
                    Newarr[i] = "0" + Convert.ToString(ii, toBase: 16);
                }
            }

            return Newarr;
        }

        public static string[] RotateColumn(string[] w)
        {
            string[] roOverrid = new string[4];
            int i = 0;
            while (i < 4)
            {
                roOverrid[i] = w[i];
                i++;
            }

            string st = roOverrid[0];
            roOverrid[0] = roOverrid[1];
            roOverrid[1] = roOverrid[2];
            roOverrid[2] = roOverrid[3];
            roOverrid[3] = st;

            return roOverrid;
        }

        public static string[,] key(int round, string[,] keymatrix)
        {
            string[,] matrix = new string[4, 4];
            string[] col4 = new string[4];
            string[] col1 = new string[4];
            string[] col2 = new string[4];
            string[] col3 = new string[4];

            for (int i = 0; i < 4; i++)
            {
                for (int y = 0; y < 4; y++)
                {
                    if (y == 0)
                    {
                        col1[i] = keymatrix[i, y];
                    }
                    else if (y == 1)
                    {
                        col2[i] = keymatrix[i, y];
                    }
                    else if (y == 2)
                    {
                        col3[i] = keymatrix[i, y];
                    }
                    else
                    {
                        col4[i] = keymatrix[i, y];
                    }
                }
            }
            string[] last_column = new string[4];
            string[] last_col = new string[4];
            for (int i = 0; i < 4; i++)
            {
                last_col[i] = col4[i];
            }
            int n = 0;

            while (n < round)
            {

                last_col = RotateColumn(col4);


                last_column = Sub_Box(last_col);

                byte[,] r = generateRcon(n);
                col1 = XOORfun(last_column, col1, r);
                col2 = XOR(col1, col2);
                col3 = XOR(col2, col3);
                col4 = XOR(col3, col4);
                n++;

            }
            for (int i = 0; i < 4; i++)
            {
                for (int y = 0; y < 4; y++)
                {
                    if (y == 0)
                    {
                        matrix[i, y] = keymatrix[i, y];
                    }
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int k = 0; k < 4; k++)
                {
                    if (k == 0)
                    {
                        matrix[i, k] = col1[i];
                    }
                    else if (k == 1)
                    {
                        matrix[i, k] = col2[i];
                    }
                    else if (k == 2)
                    {
                        matrix[i, k] = col3[i];
                    }
                    else
                    {
                        matrix[i, k] = col4[i];
                    }
                }
            }
            return matrix;
        }
    }
}