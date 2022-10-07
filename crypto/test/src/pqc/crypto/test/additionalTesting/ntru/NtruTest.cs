using System;
using System.Collections.Generic;
using System.IO;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Ntru;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using NtruKeyPairGenerator = Org.BouncyCastle.Pqc.Crypto.Ntru.NtruKeyPairGenerator;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class NtruTest
    {
        private static readonly Dictionary<string, NtruParameters> fullTestVectors = new Dictionary<string, NtruParameters>()
        {
            { "PQCkemKAT_935.rsp", NtruParameters.NtruHps2048509 },
            { "PQCkemKAT_1234.rsp", NtruParameters.NtruHps2048677 },
            { "PQCkemKAT_1590.rsp", NtruParameters.NtruHps4096821 },
            { "PQCkemKAT_1450.rsp", NtruParameters.NtruHrss701 },
        };

        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntru.",FullTests,fullTestVectors);
        }

        private static readonly Dictionary<string, NtruParameters> encapTestVectors = new Dictionary<string, NtruParameters>()
        {
            { "additionalEncapTesting_935.rsp", NtruParameters.NtruHps2048509 },
            { "additionalEncapTesting_1234.rsp", NtruParameters.NtruHps2048677 },
            { "additionalEncapTesting_1590.rsp", NtruParameters.NtruHps4096821 },
            { "additionalEncapTesting_1450.rsp", NtruParameters.NtruHrss701 },
        };
        private static readonly List<string> encapTestVectorFileNames = new List<string>(encapTestVectors.Keys);

        [TestCaseSource(nameof(encapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestEncapVectors(string encapTestVectorFile)
        {
            RunTest(encapTestVectorFile,"pqc.ntru.encapTesting.",EncapTests,encapTestVectors);
        }

        private static readonly Dictionary<string, NtruParameters> decapTestVectors = new Dictionary<string, NtruParameters>()
        {
            { "additionalDecapTesting_935.rsp", NtruParameters.NtruHps2048509 },
            { "additionalDecapTesting_1234.rsp", NtruParameters.NtruHps2048677 },
            { "additionalDecapTesting_1590.rsp", NtruParameters.NtruHps4096821 },
            { "additionalDecapTesting_1450.rsp", NtruParameters.NtruHrss701 },
        };
        private static readonly List<string> decapTestVectorFileNames = new List<string>(decapTestVectors.Keys);

        [TestCaseSource(nameof(decapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestDecapVectors(string decapTestVectorFile)
        {
            RunTest(decapTestVectorFile,"pqc.ntru.decapTesting.",DecapTests,decapTestVectors);
        }

        private static void EncapTests(string name, IDictionary<string, string> buf,Dictionary<string, NtruParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            NtruParameters parameters = paramDict[name];
            
            
            NtruPublicKeyParameters publicKeyParams = new NtruPublicKeyParameters(parameters,expectedPK);
            
            // Test encapsulate
            NtruKemGenerator encapsulationGenerator = new NtruKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] secret = encapsulatedSecret.GetSecret();
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);
        }

        private static void DecapTests(string name, IDictionary<string, string> buf,Dictionary<string, NtruParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            NtruParameters parameters = paramDict[name];

            NtruPrivateKeyParameters skParams = new NtruPrivateKeyParameters(parameters, expectedSK);
            NtruKemExtractor decapsulator = new NtruKemExtractor(skParams);
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(expectedCT);
            
            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, NtruParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            NtruParameters parameters = paramDict[name];
            
            // Key Generation.
            NtruKeyGenerationParameters generationParams = new NtruKeyGenerationParameters(random, parameters);
            
            NtruKeyPairGenerator keyGenerator = new NtruKeyPairGenerator();
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            
            NtruPublicKeyParameters publicKeyParams = (NtruPublicKeyParameters)keyPair.Public;
            NtruPrivateKeyParameters privateKeyParams = (NtruPrivateKeyParameters)keyPair.Private;
            
            // Encapsulation
            NtruKemGenerator encapsulationGenerator = new NtruKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            
            // Decapsulation
            NtruKemExtractor decapsulator = new NtruKemExtractor(privateKeyParams);
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()), "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),"FAILED session int: " + name + " " + count);

        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,NtruParameters>> testFunc,Dictionary<string,NtruParameters> parameters)
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
