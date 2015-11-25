using Uno;
using Uno.Collections;
using Fuse;
namespace Community.Cryptography
{


//MONO: Ported from: https://github.com/mono/mono/blob/8d282b527e884a93872b23b057dcb8e3166975f3/mcs/class/corlib/System.Security.Cryptography/SHA512Managed.cs
//LICENSE is in original source file.
//Ported by Sean McKay, 2015
public class SHA512  {
    private byte[] xBuf;
    private int xBufOff;
    private ulong byteCount1;
    private ulong byteCount2;
    private ulong H1, H2, H3, H4, H5, H6, H7, H8;
    private ulong[] W;
    private int wOff;
    public SHA512 ()
    {
        xBuf = new byte [8];
        W = new ulong [80];
        Initialize (false); // limited initialization
    }
    private void Initialize (bool reuse)
    {
        // SHA-512 initial hash value
        // The first 64 bits of the fractional parts of the square roots
        // of the first eight prime numbers
        H1 = 0x6a09e667f3bcc908;
        H2 = 0xbb67ae8584caa73b;
        H3 = 0x3c6ef372fe94f82b;
        H4 = 0xa54ff53a5f1d36f1;
        H5 = 0x510e527fade682d1;
        H6 = 0x9b05688c2b3e6c1f;
        H7 = 0x1f83d9abfb41bd6b;
        H8 = 0x5be0cd19137e2179;
        if (reuse) {
            byteCount1 = 0;
            byteCount2 = 0;
            xBufOff = 0;
            for (int i = 0; i < xBuf.Length; i++)
                xBuf [i] = 0;
            wOff = 0;
            for (int i = 0; i != W.Length; i++)
                W [i] = 0;
        }
    }
    public  void Initialize ()
    {
        Initialize (true); // reuse instance
    }
    // protected
    protected void HashCore (byte[] rgb, int ibStart, int cbSize)
    {
        // fill the current word
        while ((xBufOff != 0) && (cbSize > 0)) {
            update (rgb [ibStart]);
            ibStart++;
            cbSize--;
        }
        // process whole words.
        while (cbSize > xBuf.Length) {
            processWord (rgb, ibStart);
            ibStart += xBuf.Length;
            cbSize -= xBuf.Length;
            byteCount1 += (ulong) xBuf.Length;
        }
        // load in the remainder.
        while (cbSize > 0) {
            update (rgb [ibStart]);
            ibStart++;
            cbSize--;
        }
    }
    protected byte[] HashFinal ()
    {
        adjustByteCounts ();
        ulong lowBitLength = byteCount1 << 3;
        ulong hiBitLength = byteCount2;
        // add the pad bytes.
        update (128);
        while (xBufOff != 0)
           update (0);
        processLength (lowBitLength, hiBitLength);
        processBlock ();
        byte[] output = new byte [64];

        unpackWord(H1, output, 0);
        unpackWord(H2, output, 8);
        unpackWord(H3, output, 16);
        unpackWord(H4, output, 24);
        unpackWord(H5, output, 32);
        unpackWord(H6, output, 40);
        unpackWord(H7, output, 48);
        unpackWord(H8, output, 56);
        Initialize ();
        return output;
    }
    private void update (byte input)
    {
        xBuf [xBufOff++] = input;
        if (xBufOff == xBuf.Length) {
            processWord(xBuf, 0);
            xBufOff = 0;
        }
        byteCount1++;
    }
    private void processWord (byte[] input, int inOff)
    {
        W [wOff++] = ( (ulong) input [inOff] << 56)
        | ( (ulong) input [inOff + 1] << 48)
        | ( (ulong) input [inOff + 2] << 40)
        | ( (ulong) input [inOff + 3] << 32)
        | ( (ulong) input [inOff + 4] << 24)
        | ( (ulong) input [inOff + 5] << 16)
        | ( (ulong) input [inOff + 6] << 8)
        | ( (ulong) input [inOff + 7]);
        if (wOff == 16)
            processBlock ();
    }
    private void unpackWord (ulong word, byte[] output, int outOff)
    {
        
        output[outOff] = (byte) (word >> 56);
        output[outOff + 1] = (byte) (word >> 48);
        output[outOff + 2] = (byte) (word >> 40);
        output[outOff + 3] = (byte) (word >> 32);
        output[outOff + 4] = (byte) (word >> 24);
        output[outOff + 5] = (byte) (word >> 16);
        output[outOff + 6] = (byte) (word >> 8);
        output[outOff + 7] = (byte) word;

    }
    // adjust the byte counts so that byteCount2 represents the
    // upper long (less 3 bits) word of the byte count.
    private void adjustByteCounts ()
    {
        if (byteCount1 > 0x1fffffffffffffff) {
            byteCount2 += (byteCount1 >> 61);
            byteCount1 &= 0x1fffffffffffffff;
        }
    }
    private void processLength (ulong lowW, ulong hiW)
    {
        if (wOff > 14)
           processBlock();
        W[14] = hiW;
        W[15] = lowW;
    }
    private void processBlock ()
    {
        adjustByteCounts ();
        // expand 16 word block into 80 word blocks.
        for (int t = 16; t <= 79; t++)
            W[t] = Sigma1 (W [t - 2]) + W [t - 7] + Sigma0 (W [t - 15]) + W [t - 16];
        // set up working variables.
        ulong a = H1;
        ulong b = H2;
        ulong c = H3;
        ulong d = H4;
        ulong e = H5;
        ulong f = H6;
        ulong g = H7;
        ulong h = H8;
        for (int t = 0; t <= 79; t++) {
            ulong T1 = h + Sum1 (e) + Ch (e, f, g) + s_K[t] + W [t];  //ShaConstants.K2[t]
            ulong T2 = Sum0 (a) + Maj (a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        H1 += a;
        H2 += b;
        H3 += c;
        H4 += d;
        H5 += e;
        H6 += f;
        H7 += g;
        H8 += h;
        // reset the offset and clean out the word buffer.
        wOff = 0;
        for (int i = 0; i != W.Length; i++)
            W[i] = 0;
    }

        //#region Consts
        private static readonly ulong[] s_K = new ulong[]
        {
             0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
             0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
             0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
             0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
             0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
             0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
             0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
             0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
             0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
             0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
             0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
             0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
             0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
             0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
             0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
             0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
             0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
             0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
             0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
             0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };
        //#endregion

    private ulong rotateRight (ulong x, int n)
    {
        return (x >> n) | (x << (64 - n));
    }
    /* SHA-512 and SHA-512 functions (as for SHA-256 but for longs) */
    private ulong Ch (ulong x, ulong y, ulong z)
    {
        return ((x & y) ^ ((~x) & z));
    }
    private ulong Maj (ulong x, ulong y, ulong z)
    {
        return ((x & y) ^ (x & z) ^ (y & z));
    }
    private ulong Sum0 (ulong x)
    {
        return rotateRight (x, 28) ^ rotateRight (x, 34) ^ rotateRight (x, 39);
    }
    private ulong Sum1 (ulong x)
    {
        return rotateRight (x, 14) ^ rotateRight (x, 18) ^ rotateRight (x, 41);
    }
    private ulong Sigma0 (ulong x)
    {
        return rotateRight (x, 1) ^ rotateRight(x, 8) ^ (x >> 7);
    }
    private ulong Sigma1 (ulong x)
    {
        return rotateRight (x, 19) ^ rotateRight (x, 61) ^ (x >> 6);
    }


public byte[] ComputeHash (byte[] buffer)
{

    HashCore (buffer, 0, buffer.Length);
    byte[] HashValue = HashFinal ();
    Initialize ();

    return HashValue;
}    
    }

}
