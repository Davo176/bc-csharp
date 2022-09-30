using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class FalconTests
    {
        private static readonly Dictionary<string, FalconParameters> fullTestVectors = new Dictionary<string, FalconParameters>()
        {
            { "falcon512-KAT.rsp", FalconParameters.falcon_512 },
            { "falcon1024-KAT.rsp", FalconParameters.falcon_1024 },
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.falcon.",FullTests,fullTestVectors);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, FalconParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            uint m_len = uint.Parse(buf["mlen"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedSM = Hex.Decode(buf["sm"]);
            uint expectedSMLEN = uint.Parse(buf["smlen"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            FalconParameters parameters = paramDict[name];

            // Key Generation
            FalconKeyPairGenerator keyGenerator = new FalconKeyPairGenerator();
            FalconKeyGenerationParameters generationParams = new FalconKeyGenerationParameters(random, parameters);
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            FalconPublicKeyParameters publicKeyParams = (FalconPublicKeyParameters) keyPair.Public;
            FalconPrivateKeyParameters privateKeyParams = (FalconPrivateKeyParameters) keyPair.Private;

            // Sign
            FalconSigner signer = new FalconSigner();
            FalconPrivateKeyParameters skparam = new FalconPrivateKeyParameters(parameters, expectedSK);
            ParametersWithRandom skwrand = new ParametersWithRandom(skparam, random);
            signer.Init(true, skwrand);
            byte[] sig = signer.GenerateSignature(msg);
            byte[] ressm = new byte[2 + msg.Length + sig.Length - 1];
            ressm[0] = (byte)((sig.Length - 40 - 1) >> 8);
            ressm[1] = (byte)(sig.Length - 40 - 1);
            Array.Copy(sig, 1, ressm, 2, 40);
            Array.Copy(msg, 0, ressm, 2 + 40, msg.Length);
            Array.Copy(sig, 40 + 1, ressm, 2 + 40 + msg.Length, sig.Length - 40 - 1);

            // Verify
            FalconSigner verifier = new FalconSigner();
            FalconPublicKeyParameters pkparam = new FalconPublicKeyParameters(parameters, expectedPK);
            verifier.Init(false, pkparam);
            byte[] noncesig = new byte[expectedSMLEN - m_len - 2 + 1];
            noncesig[0] = (byte)(0x30 + parameters.LogN);
            Array.Copy(expectedSM, 2, noncesig, 1, 40);
            Array.Copy(expectedSM, 2 + 40 + m_len, noncesig, 40 + 1, expectedSMLEN - 2 - 40 - m_len);
            bool vrfyrespass = verifier.VerifySignature(msg, noncesig);
            noncesig[42]++; // changing the signature by 1 byte should cause it to fail
            bool vrfyresfail = verifier.VerifySignature(msg, noncesig);

            // Assert.True
            //keyGenerator
            Assert.True(Arrays.AreEqual(publicKeyParams.GetEncoded(), expectedPK), name + " " + count + " public key");
            Assert.True(Arrays.AreEqual(privateKeyParams.GetEncoded(), expectedSK), name + " " + count + " private key");
            //sign
            Assert.True(Arrays.AreEqual(ressm, expectedSM), name + " " + count + " signature");
            //verify
            Assert.True(vrfyrespass, name + " " + count + " verify failed when should pass");
            Assert.False(vrfyresfail, name + " " + count + " verify passed when should fail");
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,FalconParameters>> testFunc,Dictionary<string,FalconParameters> parameters)
        {
            var buf = new Dictionary<string, string>();

            using (var src = new StreamReader(SimpleTest.GetTestDataAsStream(partialLocation + name)))
            {
                string line;
                while ((line = src.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.StartsWith("#"))
                        continue;

                    if (line.Length > 0)
                    {
                        int a = line.IndexOf('=');
                        if (a > -1)
                        {
                            buf[line.Substring(0, a).Trim()] = line.Substring(a + 1).Trim();
                        }
                        continue;
                    }

                    if (buf.Count > 0)
                    {
                        testFunc(name, buf,parameters);
                        buf.Clear();
                    }
                }

                if (buf.Count > 0)
                {
                    testFunc(name, buf,parameters);
                }
            }
        }
    }
}
