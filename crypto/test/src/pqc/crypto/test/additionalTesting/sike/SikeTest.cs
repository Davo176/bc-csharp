using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class SikeTests
    {
        private static readonly Dictionary<string, SIKEParameters> fullTestVectors = new Dictionary<string, SIKEParameters>()
        {
            { "PQCkemKAT_374.rsp" , SIKEParameters.sikep434 },
            { "PQCkemKAT_434.rsp" , SIKEParameters.sikep503 },
            { "PQCkemKAT_524.rsp" , SIKEParameters.sikep610 },
            { "PQCkemKAT_644.rsp" , SIKEParameters.sikep751 },
            { "PQCkemKAT_350.rsp" , SIKEParameters.sikep434_compressed },
            { "PQCkemKAT_407.rsp" , SIKEParameters.sikep503_compressed },
            { "PQCkemKAT_491.rsp" , SIKEParameters.sikep610_compressed },
            { "PQCkemKAT_602.rsp" , SIKEParameters.sikep751_compressed }
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        private static readonly Dictionary<string, SIKEParameters> addFullTestVectors = new Dictionary<string, SIKEParameters>()
        {
            { "addRandTest_374.rsp" , SIKEParameters.sikep434 },
            { "addRandTest_503.rsp" , SIKEParameters.sikep503 },
            { "addRandTest_610.rsp" , SIKEParameters.sikep610 },
            { "addRandTest_751.rsp" , SIKEParameters.sikep751 },
        };

        private static readonly List<string> fullAddTestVectorFileNames = new List<string>(addFullTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sike.",FullTests,fullTestVectors);
        }

        [TestCaseSource(nameof(fullAddTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sike.additionalRandomTesting.",FullTests,addFullTestVectors);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, SIKEParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);      // seed for SIKE secure random
            byte[] expectedPK = Hex.Decode(buf["pk"]);          // public key
            byte[] expectedSK = Hex.Decode(buf["sk"]);          // private key
            byte[] expectedCT = Hex.Decode(buf["ct"]);          // cipher text
            byte[] expectedSS = Hex.Decode(buf["ss"]);          // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            SIKEParameters parameters = paramDict[name];

            SIKEKeyPairGenerator keyGenerator = new SIKEKeyPairGenerator();
            SIKEKeyGenerationParameters generationParams = new SIKEKeyGenerationParameters(random, parameters);


            // Key Generation
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            
            SIKEPublicKeyParameters publicKeyParams = (SIKEPublicKeyParameters) keyPair.Public;
            SIKEPrivateKeyParameters privateKeyParams = (SIKEPrivateKeyParameters)keyPair.Private;

            // Encapsulation
            SIKEKEMGenerator encapsulationGenerator = new SIKEKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            // KEM Dec
            SIKEKEMExtractor decapsulator = new SIKEKEMExtractor(privateKeyParams);
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()),"FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()),"FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),"FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, secret),   "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, expectedSS),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),"FAILED session int: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,SIKEParameters>> testFunc,Dictionary<string,SIKEParameters> parameters)
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
