using Org.BouncyCastle.Utilities;
using System;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber
{
    public class KyberPrivateKeyParameters
        : KyberKeyParameters
    {
        private readonly byte[] m_s;
        private readonly byte[] m_hpk;
        private readonly byte[] m_nonce;
        private readonly byte[] m_t;
        private readonly byte[] m_rho;

        public KyberPrivateKeyParameters(KyberParameters parameters, byte[] s, byte[] hpk, byte[] nonce, byte[] t, byte[] rho)
            : base(true, parameters)
        {
            m_s = Arrays.Clone(s);
            m_hpk = Arrays.Clone(hpk);
            m_nonce = Arrays.Clone(nonce);
            m_t = Arrays.Clone(t);
            m_rho = Arrays.Clone(rho);
        }
        public KyberPrivateKeyParameters(KyberParameters parameters, byte[] sk)
            : base(true, parameters)
        {
            KyberEngine engine= parameters.Engine;
            int sLength = engine.IndCpaSecretKeyBytes;
            int hpkLength = 32;
            int nonceLength = KyberEngine.SymBytes;
            int tLength = engine.IndCpaPublicKeyBytes-32;
            int rhoLength = 32; 

            m_s = Arrays.CopyOfRange(sk,0,sLength);
            m_t = Arrays.CopyOfRange(sk,sLength,sLength+tLength);
            m_rho = Arrays.CopyOfRange(sk,sLength+tLength,sLength+tLength+rhoLength);
            m_hpk = Arrays.CopyOfRange(sk,sLength+tLength+nonceLength,sLength+tLength+nonceLength+rhoLength);
            m_nonce = Arrays.CopyOfRange(sk,sLength+tLength+rhoLength+hpkLength,sk.Length);
        }


        public byte[] GetEncoded()
        {
            return Arrays.ConcatenateAll(m_s, m_t, m_rho, m_hpk, m_nonce);
        }

        internal byte[] S => m_s;
        internal byte[] Hpk => m_hpk;
        internal byte[] Nonce => m_nonce;
        internal byte[] T => m_t;
        internal byte[] Rho => m_rho;

    }
}