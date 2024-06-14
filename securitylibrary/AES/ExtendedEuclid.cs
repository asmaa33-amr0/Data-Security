using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>

        int a1, a2, a3, b1, b2, b3;
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            a1 = 1; a2 = 0; a3 = baseN;
            b1 = 0; b2 = 1; b3 = number;
            while (b3 != 0)
            {
                if (b3 == 1)
                {
                    if (b2 < 0)
                    {
                        b2 += baseN;
                    }
                    return b2;
                }
                int q = a3 / b3;
                int t1 = a1 - (q * b1), t2 = a2 - (q * b2), t3 = a3 - (q * b3);
                a1 = b1; a2 = b2; a3 = b3;
                b1 = t1; b2 = t2; b3 = t3;
            }
            return -1;

        }
    }
}