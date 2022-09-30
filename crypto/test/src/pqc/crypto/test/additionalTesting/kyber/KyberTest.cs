using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class KyberTest
    {
        private static readonly Dictionary<string, KyberParameters> fullTestVectors = new Dictionary<string, KyberParameters>()
        {
            //{ "kyber512.rsp", KyberParameters.kyber512 },
            // { "kyber768.rsp", KyberParameters.kyber768 },
             { "kyber1024.rsp", KyberParameters.kyber1024 }
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        private static readonly Dictionary<string, KyberParameters> encapTestVectors = new Dictionary<string, KyberParameters>()
        {
            { "additionalEncapTesting1632.rsp", KyberParameters.kyber512 },
            { "additionalEncapTesting2400.rsp", KyberParameters.kyber768 },
            { "additionalEncapTesting3168.rsp", KyberParameters.kyber1024 }
        };

        private static readonly List<string> encapTestVectorFileNames = new List<string>(encapTestVectors.Keys);

        private static readonly Dictionary<string, KyberParameters> decapTestVectors = new Dictionary<string, KyberParameters>()
        {
            { "additionalDecapTesting1632.rsp", KyberParameters.kyber512 },
            { "additionalDecapTesting2400.rsp", KyberParameters.kyber768 },
            { "additionalDecapTesting3168.rsp", KyberParameters.kyber1024 }
        };

        private static readonly List<string> decapTestVectorFileNames = new List<string>(decapTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.crystals.kyber.",FullTests,fullTestVectors);
        }

        [TestCaseSource(nameof(encapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestEncapVectors(string encapTestVectorFile)
        {
            RunTest(encapTestVectorFile,"pqc.crystals.kyber.encapTesting.",testEncap,encapTestVectors);
        }

        [TestCaseSource(nameof(decapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestDecapVectors(string encapTestVectorFile)
        {
            RunTest(encapTestVectorFile,"pqc.crystals.kyber.decapTesting.",testDecap,decapTestVectors);
        }

        private static void testEncap(string name, IDictionary<string, string> buf,Dictionary<string, KyberParameters> paramDict)
        {
            String count = buf["count"];

            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]); 
            byte[] expectedCT = Hex.Decode(buf["ct"]); 
            byte[] expectedSS = Hex.Decode(buf["ss"]); 

            NistSecureRandom random = new NistSecureRandom(seed, null);
            KyberParameters parameters = paramDict[name];

            // KEM Enc
            KyberPublicKeyParameters publicKeyParams = new KyberPublicKeyParameters(parameters,expectedPK);
            KyberKEMGenerator encapsulationGenerator = new KyberKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),                        "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length),   "FAILED session enc: " + name + " " + count);
        }
        private static void testDecap(string name, IDictionary<string, string> buf,Dictionary<string, KyberParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]); 
            byte[] expectedCT = Hex.Decode(buf["ct"]); 
            byte[] expectedSS = Hex.Decode(buf["ss"]); 

            NistSecureRandom random = new NistSecureRandom(seed, null);
            KyberParameters parameters = paramDict[name];

            KyberPrivateKeyParameters privateKeyParams = new KyberPrivateKeyParameters(parameters,expectedSK);

            // KEM Dec
            KyberKEMExtractor decapsulator = new KyberKEMExtractor(privateKeyParams);

            byte[] decapsulatedSecret = decapsulator.ExtractSecret(expectedCT);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, KyberParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]); 
            byte[] expectedSK = Hex.Decode(buf["sk"]); 
            byte[] expectedCT = Hex.Decode(buf["ct"]); 
            byte[] expectedSS = Hex.Decode(buf["ss"]); 

            NistSecureRandom random = new NistSecureRandom(seed, null);
            KyberParameters parameters = paramDict[name];

            KyberKeyPairGenerator keysGenerator = new KyberKeyPairGenerator();
            KyberKeyGenerationParameters generationParams = new KyberKeyGenerationParameters(random, parameters);

            // Key Generation.

            keysGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

            KyberPublicKeyParameters publicKeyParams = (KyberPublicKeyParameters)keys.Public;
            KyberPrivateKeyParameters privateKeyParams = (KyberPrivateKeyParameters)keys.Private;

            // Encapsulation
            KyberKEMGenerator encapsulationGenerator = new KyberKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            
            // Decapsulation
            KyberKEMExtractor decapsulator = new KyberKEMExtractor(privateKeyParams);

            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Console.WriteLine(Hex.ToHexString(expectedSS));
            Console.WriteLine(Hex.ToHexString(secret));

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()),                "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()),                "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),                        "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length),   "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),                                          "FAILED session int: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,KyberParameters>> testFunc,Dictionary<string,KyberParameters> parameters)
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
