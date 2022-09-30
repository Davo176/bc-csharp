using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class CmceTest
    {
        private static readonly Dictionary<string, CmceParameters> partialTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "3488-64-cmce.txt", CmceParameters.mceliece348864r3 },
            { "3488-64-f-cmce.txt", CmceParameters.mceliece348864fr3 },
            { "4608-96-cmce.txt", CmceParameters.mceliece460896r3 },
            { "4608-96-f-cmce.txt", CmceParameters.mceliece460896fr3 },
            { "6688-128-cmce.txt", CmceParameters.mceliece6688128r3 },
            { "6688-128-f-cmce.txt", CmceParameters.mceliece6688128fr3 },
            { "6960-119-cmce.txt", CmceParameters.mceliece6960119r3 },
            { "6960-119-f-cmce.txt", CmceParameters.mceliece6960119fr3 },
            { "8192-128-cmce.txt", CmceParameters.mceliece8192128r3 },
            { "8192-128-f-cmce.txt", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> partialTestVectorFileNames = new List<string>(partialTestVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> fullTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "348864cmce.rsp", CmceParameters.mceliece348864r3 },
            { "348864fcmce.rsp", CmceParameters.mceliece348864fr3 },
            { "460896cmce.rsp", CmceParameters.mceliece460896r3 },
            { "460896fcmce.rsp", CmceParameters.mceliece460896fr3 },
            { "6688128cmce.rsp", CmceParameters.mceliece6688128r3 },
            { "6688128fcmce.rsp", CmceParameters.mceliece6688128fr3 },
            { "6960119cmce.rsp", CmceParameters.mceliece6960119r3 },
            { "6960119fcmce.rsp", CmceParameters.mceliece6960119fr3 },
            { "8192128cmce.rsp", CmceParameters.mceliece8192128r3 },
            { "8192128fcmce.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        [TestCaseSource(nameof(partialTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestPartialVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.cmce.",FullTests,partialTestVectors);
        }

        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.cmce.additionalTesting.full",FullTests,fullTestVectors);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, CmceParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            CmceParameters parameters = paramDict[name];

            CmceKeyPairGenerator keysGenerator = new CmceKeyPairGenerator();
            CmceKeyGenerationParameters generationParams = new CmceKeyGenerationParameters(random, parameters);

            // Key Generation.

            keysGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

            CmcePublicKeyParameters publicKeyParams = (CmcePublicKeyParameters) keys.Public;
            CmcePrivateKeyParameters privateKeyParams = (CmcePrivateKeyParameters) keys.Private;

            
            // KEM Enc
            CmceKemGenerator encapsulationGenerator = new CmceKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            
            // KEM Dec
            CmceKemExtractor decapsulator = new CmceKemExtractor(privateKeyParams);

            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()),                "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()),                "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),                               "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, secret),   "FAILED session enc: " + name + " " + count);

            //Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, expectedSS),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),                                "FAILED session enc: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,CmceParameters>> testFunc,Dictionary<string,CmceParameters> parameters)
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
