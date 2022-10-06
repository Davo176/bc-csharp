using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Saber;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class SaberTest
    {
        private static readonly Dictionary<string, SABERParameters> addRandTestVectors = new Dictionary<string, SABERParameters>()
        {
            { "addRand_1568.rsp", SABERParameters.lightsaberkem256r3 },
            { "addRand_2304.rsp", SABERParameters.saberkem256r3 },
            { "addRand_3040.rsp", SABERParameters.firesaberkem256r3 }
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(addRandTestVectors.Keys);

        private static readonly Dictionary<string, SABERParameters> encapTestVectors = new Dictionary<string, SABERParameters>()
        {
            { "additionalEncapTesting_1568.rsp", SABERParameters.lightsaberkem256r3 },
            { "additionalEncapTesting_2304.rsp", SABERParameters.saberkem256r3 },
            { "additionalEncapTesting_3040.rsp", SABERParameters.firesaberkem256r3 }
        };
        private static readonly List<string> encapTestVectorFileNames = new List<string>(encapTestVectors.Keys);
        
        private static readonly Dictionary<string, SABERParameters> decapTestVectors = new Dictionary<string, SABERParameters>()
        {
            { "additionalDecapTesting_1568.rsp", SABERParameters.lightsaberkem256r3 },
            { "additionalDecapTesting_2304.rsp", SABERParameters.saberkem256r3 },
            { "additionalDecapTesting_3040.rsp", SABERParameters.firesaberkem256r3 }
        };
        private static readonly List<string> decapTestVectorFileNames = new List<string>(decapTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string TestVectorFile)
        {
            RunTest(TestVectorFile,"pqc.saber.randTesting.",FullTests,addRandTestVectors);
        }

        [TestCaseSource(nameof(encapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestEncapVectors(string encapTestVectorFile)
        {
            RunTest(encapTestVectorFile,"pqc.saber.encapTesting.",EncapTests,encapTestVectors);
        }

        [TestCaseSource(nameof(decapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestDecapVectors(string decapTestVectorFile)
        {
            RunTest(decapTestVectorFile,"pqc.saber.decapTesting.",DecapTests,decapTestVectors);
        }

        private static void EncapTests(string name, IDictionary<string, string> buf,Dictionary<string, SABERParameters> paramDict)
        {
            String count = buf["count"];

            byte[] seed = Hex.Decode(buf["seed"]); // seed for SABER secure random
            byte[] expectedPK = Hex.Decode(buf["pk"]); // public key
            byte[] expectedCT = Hex.Decode(buf["ct"]); // ciphertext
            byte[] expectedSS = Hex.Decode(buf["ss"]); // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            SABERParameters parameters = paramDict[name];

            // KEM Enc
            SABERKEMGenerator encapsulationGenerator = new SABERKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(new SABERPublicKeyParameters(parameters,expectedPK));
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);
        }

        private static void DecapTests(string name, IDictionary<string, string> buf,Dictionary<string, SABERParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]); // seed for SABER secure random
            byte[] expectedSK = Hex.Decode(buf["sk"]); // private key
            byte[] expectedCT = Hex.Decode(buf["ct"]); // ciphertext
            byte[] expectedSS = Hex.Decode(buf["ss"]); // session key

            SABERParameters parameters = paramDict[name];
            // KEM Dec
            SABERKEMExtractor decapsulator = new SABERKEMExtractor(new SABERPrivateKeyParameters(parameters,expectedSK));
 
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(expectedCT);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
        }
        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, SABERParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            SABERParameters parameters = paramDict[name];

            SABERKeyPairGenerator keyGenerator = new SABERKeyPairGenerator();
            SABERKeyGenerationParameters generationParams = new SABERKeyGenerationParameters(random, parameters);
            
            // Key Generation.
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            SABERPublicKeyParameters publicKeyParams = (SABERPublicKeyParameters) keyPair.Public;
            SABERPrivateKeyParameters privateKeyParams = (SABERPrivateKeyParameters) keyPair.Private;
            
            // Encapsulation
            SABERKEMGenerator encapsulationGenerator = new SABERKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            
            // Decapsulation
            SABERKEMExtractor decapsulator = new SABERKEMExtractor(privateKeyParams);
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()), "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),"FAILED session int: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,SABERParameters>> testFunc,Dictionary<string,SABERParameters> parameters)
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
