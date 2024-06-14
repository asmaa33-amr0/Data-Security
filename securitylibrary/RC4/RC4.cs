using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;
namespace SecurityLibrary.RC4
{
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string plain = "";
            plain = Encrypt(cipherText, key);
            return plain;
        }

        public override string Encrypt(string plainText, string key)
        {
            bool have_x0 = false;
            if (plainText[0] == '0' && plainText[1] == 'x')
            {
                have_x0 = true;
                plainText = plainText.Remove(0, 2);
                key = key.Remove(0, 2);
                string temp_key = key;
                string temp_pain = plainText;
                key = "";
                plainText = "";

                for (int i = 0; i < temp_pain.Length; i += 2)
                {
                    string hexPair = temp_pain.Substring(i, 2);
                    //  convert hexa to int then int to Unicode character 2 hex will be one char 
                    plainText += (char)int.Parse(hexPair, System.Globalization.NumberStyles.HexNumber);

                    hexPair = temp_key.Substring(i, 2);
                    key += (char)int.Parse(hexPair, System.Globalization.NumberStyles.HexNumber);
                }


            }

            int[] S_arr = new int[256];
            int[] T_arr = new int[256];
            for (int i = 0; i < 256; i++)
            {
                S_arr[i] = i;
                T_arr[i] = key[i % key.Length];
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S_arr[i] + T_arr[i]) % 256;
                int temp_swap = S_arr[i];
                S_arr[i] = S_arr[j];
                S_arr[j] = temp_swap;
            }



            int t;

            int ii = 0, jj = 0;
            string cipher = "";
            for (int c = 0; c < plainText.Length; c++)
            {

                ii = (ii + 1) % 256;
                jj = (jj + S_arr[ii]) % 256;
                int tmp;
                tmp = S_arr[ii];
                S_arr[ii] = S_arr[jj];
                S_arr[jj] = tmp;
                t = (S_arr[ii] + S_arr[jj]) % 256;
                //XOR plain , key 
                cipher += (char)(plainText[c] ^ S_arr[t]);
            }

            string cipherText = cipher;

            if (have_x0)
            {
                //add "0x" in case hexa and convert the 1-char to int 2- int to hexa and "x" for hexa   
                cipherText = "0x" + string.Concat(cipherText.Select(c => ((int)c).ToString("x")));
            }

            return cipherText;


        }
    }
}
