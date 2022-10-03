using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class DilithiumTest
    {
        private static readonly Dictionary<string, DilithiumParameters> fullTestVectors = new Dictionary<string, DilithiumParameters>()
        {
            { "PQCsignKAT_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
            { "PQCsignKAT_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
            { "PQCsignKAT_Dilithium5.rsp", DilithiumParameters.Dilithium5 }
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        private static readonly Dictionary<string, DilithiumParameters> signTestVectors = new Dictionary<string, DilithiumParameters>()
        {
            { "addSignTest_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
            { "addSignTest_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
            { "addSignTest_Dilithium5.rsp", DilithiumParameters.Dilithium5 }
        };

        private static readonly List<string> signTestVectorFileNames = new List<string>(signTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.crystals.dilithium.",FullTests,fullTestVectors);
        }

        [TestCaseSource(nameof(signTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestSignVectors(string signTestVectorFile)
        {
            RunTest(signTestVectorFile,"pqc.crystals.dilithium.signVectors.",testSign,signTestVectors);
        }

        private static void testSign(string name, IDictionary<string, string> buf,Dictionary<string, DilithiumParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            int mlen = int.Parse(buf["mlen"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            int expectedSMLEN = int.Parse(buf["smlen"]);
            byte[] expectedSM = Hex.Decode(buf["sm"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            DilithiumParameters parameters = paramDict[name];

            DilithiumSigner signer = new DilithiumSigner();
            DilithiumPrivateKeyParameters privateKeyParams = new DilithiumPrivateKeyParameters(parameters,expectedSK,random);

            signer.Init(true, privateKeyParams);
            byte[] generatedSM = signer.GenerateSignature(msg);
            byte[] finalSM = Arrays.ConcatenateAll(generatedSM, msg);

            Assert.True(expectedSMLEN == finalSM.Length, "FAILED signature length: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSM, finalSM), "FAILED signature gen: " + name + " " + count);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, DilithiumParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            int mlen = int.Parse(buf["mlen"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            int expectedSMLEN = int.Parse(buf["smlen"]);
            byte[] expectedSM = Hex.Decode(buf["sm"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            DilithiumParameters parameters = paramDict[name];

            DilithiumKeyPairGenerator keyGenerator = new DilithiumKeyPairGenerator();
            DilithiumKeyGenerationParameters generationParams = new DilithiumKeyGenerationParameters(random, parameters);

            // Key Generation
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            DilithiumPublicKeyParameters publicKeyParams = (DilithiumPublicKeyParameters) keyPair.Public;
            DilithiumPrivateKeyParameters privateKeyParams = (DilithiumPrivateKeyParameters) keyPair.Private;

            // Sign
            DilithiumSigner signer = new DilithiumSigner();

            signer.Init(true, privateKeyParams);
            byte[] generatedSM = signer.GenerateSignature(msg);
            byte[] finalSM = Arrays.ConcatenateAll(generatedSM, msg);

            // Verify
            signer.Init(false, publicKeyParams);
            Boolean validSignature = signer.VerifySignature(msg, generatedSM);

            Assert.True(Arrays.AreEqual(expectedPK, publicKeyParams.GetEncoded()), "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), "FAILED secret key: " + name + " " + count);

            Assert.True(expectedSMLEN == finalSM.Length, "FAILED signature length: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSM, finalSM), "FAILED signature gen: " + name + " " + count);

            Assert.True(validSignature, "FAILED signature verify: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,DilithiumParameters>> testFunc,Dictionary<string,DilithiumParameters> parameters)
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
