using Uno;
using Uno.Collections;
using Uno.Text;
using Fuse;

namespace Community.Cryptography
{

    //Sha256 algorithm from: http://hashlib.codeplex.com/
    //License: http://hashlib.codeplex.com/license CDDL

    // PORTED TO UNO WITH BASIC REFACTORING: Sean McKay, 2015

    public class Converters
    {    	

        public static string ConvertBytesToHexString (byte[] a_in, bool a_group = true)
        {
            string hex = BitConverter.ToString (a_in).ToUpper ();

            if (a_group) {

                string[] ar = BitConverter.ToString (a_in).ToUpper ().Split (new char[] { '-' });

                hex = "";

                for (int i = 0; i < ar.Length / 4; i++) {
                    if (i != 0)
                        hex += "-";
                    hex += ar [i * 4] + ar [i * 4 + 1] + ar [i * 4 + 2] + ar [i * 4 + 3];
                }
            } else
                hex = hex.Replace ("-", "");

            return hex;
        }

        public static byte[] ConvertUIntsToBytesSwapOrder (uint[] a_in, int a_index = 0, int a_length = -1)
        {
            if (a_length == -1)
                a_length = a_in.Length;

            byte[] result = new byte[a_length * 4];

            for (int j = 0; a_length > 0;  a_index++) {
                result [j++] = (byte)(a_in [a_index] >> 24);
                result [j++] = (byte)(a_in [a_index] >> 16);
                result [j++] = (byte)(a_in [a_index] >> 8);
                result [j++] = (byte)a_in [a_index];
                a_length--;
            }

            return result;
        }

        public static void ConvertBytesToUIntsSwapOrder (byte[] a_in, int a_index, int a_length, uint[] a_result, int a_index_out)
        {
            for (int i = a_index_out; a_length > 0; a_length -= 4) {
                a_result [i++] =
                    ((uint)a_in [a_index++] << 24) |
                ((uint)a_in [a_index++] << 16) |
                ((uint)a_in [a_index++] << 8) |
                a_in [a_index++];
            }
        }

        public static void ConvertULongToBytesSwapOrder (ulong a_in, byte[] a_out, int a_index)
        {
            //Debug.Assert (a_index + 8 <= a_out.Length);

            a_out [a_index++] = (byte)(a_in >> 56);
            a_out [a_index++] = (byte)(a_in >> 48);
            a_out [a_index++] = (byte)(a_in >> 40);
            a_out [a_index++] = (byte)(a_in >> 32);
            a_out [a_index++] = (byte)(a_in >> 24);
            a_out [a_index++] = (byte)(a_in >> 16);
            a_out [a_index++] = (byte)(a_in >> 8);
            a_out [a_index++] = (byte)a_in;
        }

    }

    public class SHA256
    {
        protected readonly uint[] m_state = new uint[8];

        private readonly HashBuffer m_buffer;
        protected ulong m_processed_bytes;
        private readonly int m_block_size;
        private readonly int m_hash_size;

        public static int BUFFER_SIZE = 64 * 1024;


        #region Consts

        private static readonly uint[] s_K = new uint[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        #endregion

        #region ctors

        public SHA256 ()
            : this (32)
        {
        }

      

        public SHA256 (int a_hash_size)
            : this (a_hash_size, 64)
        {
            Initialize ();
        }


        protected SHA256 (int a_hash_size, int a_block_size, int a_buffer_size = -1)
        {
            if (a_buffer_size == -1)
                a_buffer_size = a_block_size;

            m_buffer = new HashBuffer (a_buffer_size);
            m_processed_bytes = 0;
            //Debug.Assert ((a_block_size > 0) || (a_block_size == -1));
            //Debug.Assert (a_hash_size > 0);

            m_block_size = a_block_size;
            m_hash_size = a_hash_size;
        }

        #endregion

        public void Initialize ()
        {
            m_state [0] = 0x6a09e667;
            m_state [1] = 0xbb67ae85;
            m_state [2] = 0x3c6ef372;
            m_state [3] = 0xa54ff53a;
            m_state [4] = 0x510e527f;
            m_state [5] = 0x9b05688c;
            m_state [6] = 0x1f83d9ab;
            m_state [7] = 0x5be0cd19;

            m_buffer.Initialize ();
            m_processed_bytes = 0;
        }

        public byte[] ComputeHash (byte[] input)
        {
            Initialize ();
            TransformBytes (input, 0, input.Length);
            return TransformFinal ();
        }

        protected byte[] GetResult ()
        {
            return Converters.ConvertUIntsToBytesSwapOrder (m_state);
        }



        protected void Finish ()
        {
            ulong bits = m_processed_bytes * 8;
            int padindex = (m_buffer.Pos < 56) ? (56 - m_buffer.Pos) : (120 - m_buffer.Pos);

            byte[] pad = new byte[padindex + 8];
            pad [0] = 0x80;

            Converters.ConvertULongToBytesSwapOrder (bits, pad, padindex);
            padindex += 8;

            TransformBytes (pad, 0, padindex);
        }

        protected void TransformBlock (byte[] a_data, int a_index)
        {
            uint[] data = new uint[64];
            Converters.ConvertBytesToUIntsSwapOrder (a_data, a_index, m_block_size, data, 0);

            uint A = m_state [0];
            uint B = m_state [1];
            uint C = m_state [2];
            uint D = m_state [3];
            uint E = m_state [4];
            uint F = m_state [5];
            uint G = m_state [6];
            uint H = m_state [7];

            for (int r = 16; r < 64; r++) {
                uint T = data [r - 2];
                uint T2 = data [r - 15];
                data [r] = (((T >> 17) | (T << 15)) ^ ((T >> 19) | (T << 13)) ^ (T >> 10)) + data [r - 7] +
                (((T2 >> 7) | (T2 << 25)) ^ ((T2 >> 18) | (T2 << 14)) ^ (T2 >> 3)) + data [r - 16];
            }

            for (int r = 0; r < 64; r++) {
                uint T = s_K [r] + data [r] + H + (((E >> 6) | (E << 26)) ^ ((E >> 11) | (E << 21)) ^ ((E >> 25) |
                         (E << 7))) + ((E & F) ^ (~E & G));
                uint T2 = (((A >> 2) | (A << 30)) ^ ((A >> 13) | (A << 19)) ^
                          ((A >> 22) | (A << 10))) + ((A & B) ^ (A & C) ^ (B & C));
                H = G;
                G = F;
                F = E;
                E = D + T;
                D = C;
                C = B;
                B = A;
                A = T + T2;
            }

            m_state [0] += A;
            m_state [1] += B;
            m_state [2] += C;
            m_state [3] += D;
            m_state [4] += E;
            m_state [5] += F;
            m_state [6] += G;
            m_state [7] += H;
        }


        public void TransformBytes (byte[] a_data, int a_index, int a_length)
        {
            //Debug.Assert (a_index >= 0);
            //Debug.Assert (a_length >= 0);
            //Debug.Assert (a_index + a_length <= a_data.Length);

            if (!m_buffer.IsEmpty) {
                if (m_buffer.Feed (a_data, ref a_index, ref a_length, ref m_processed_bytes))
                    TransformBlock (m_buffer.GetBytes (), 0);
            }

            while (a_length >= m_buffer.Length) {
                m_processed_bytes += (ulong)m_buffer.Length;
                TransformBlock (a_data, a_index);
                a_index += m_buffer.Length;
                a_length -= m_buffer.Length;
            }

            if (a_length > 0)
                m_buffer.Feed (a_data, ref a_index, ref a_length, ref m_processed_bytes);
        }


        public byte[] TransformFinal ()
        {
            Finish ();
            //Debug.Assert (m_buffer.IsEmpty);
            byte[] result = GetResult ();
            //Debug.Assert (result.Length == HashSize);
            Initialize ();
            return result;
        }
            
    }

    internal class HashBuffer
    {
        private byte[] m_data;
        private int m_pos;

        public HashBuffer (int a_length)
        {
            //Debug.Assert (a_length > 0);

            m_data = new byte[a_length];

            Initialize ();
        }

        public void Initialize ()
        {
            m_pos = 0;
        }

        public byte[] GetBytes ()
        {
            //Debug.Assert (IsFull);

            m_pos = 0;
            return m_data;
        }

        public byte[] GetBytesZeroPadded ()
        {
            BitConverter.Clear (m_data, m_pos, m_data.Length - m_pos); 
            m_pos = 0;
            return m_data;
        }

        public bool Feed (byte[] a_data, ref int a_start_index, ref int a_length, ref ulong a_processed_bytes)
        {
            //Debug.Assert (a_start_index >= 0);
            //Debug.Assert (a_length >= 0);
            //Debug.Assert (a_start_index + a_length <= a_data.Length);
            //Debug.Assert (!IsFull);

            if (a_data.Length == 0)
                return false;

            if (a_length == 0)
                return false;

            int length = m_data.Length - m_pos;
            if (length > a_length)
                length = a_length;

            Array.Copy (a_data, a_start_index, m_data, m_pos, length);

            m_pos += length;
            a_start_index += length;
            a_length -= length;
            a_processed_bytes += (ulong)length;

            return IsFull;
        }

        public bool Feed (byte[] a_data, int a_length)
        {
            //Debug.Assert (a_length >= 0);
            //Debug.Assert (a_length <= a_data.Length);
            //Debug.Assert (!IsFull);

            if (a_data.Length == 0)
                return false;

            if (a_length == 0)
                return false;

            int length = m_data.Length - m_pos;
            if (length > a_length)
                length = a_length;

            Array.Copy (a_data, 0, m_data, m_pos, length);

            m_pos += length;

            return IsFull;
        }

        public bool IsEmpty {
            get {
                return m_pos == 0;
            }
        }

        public int Pos {
            get {
                return m_pos;
            }
        }

        public int Length {
            get {
                return m_data.Length;
            }
        }

        public bool IsFull {
            get {
                return (m_pos == m_data.Length);
            }
        }

        public override string ToString ()
        {
            return String.Format ("HashBuffer, Legth: {0}, Pos: {1}, IsEmpty: {2}", Length, Pos, IsEmpty);
        }
    }
}
