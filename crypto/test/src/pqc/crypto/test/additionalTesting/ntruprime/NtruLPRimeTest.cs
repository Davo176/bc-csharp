using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.NtruPrime;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class NTRULPrimeTest
    {
        private static readonly Dictionary<string, NtruLPRimeParameters> LPRaddRandTestVectors = new Dictionary<string, NtruLPRimeParameters>()
        {
            { "addRand653.rsp", NtruLPRimeParameters.ntrulpr653 },
            { "addRand761.rsp", NtruLPRimeParameters.ntrulpr761 },
            { "addRand857.rsp", NtruLPRimeParameters.ntrulpr857 },
            { "addRand953.rsp", NtruLPRimeParameters.ntrulpr953 },
            { "addRand1013.rsp", NtruLPRimeParameters.ntrulpr1013 },
            { "addRand1277.rsp", NtruLPRimeParameters.ntrulpr1277 }, //fail (error caused by HEX?)
        };
        private static readonly List<string> LPRaddRandTestVectorFileNames = new List<string>(LPRaddRandTestVectors.Keys);

        private static readonly Dictionary<string, NtruLPRimeParameters> LPREncapTestVectors = new Dictionary<string, NtruLPRimeParameters>()
        {
            { "addEncap653.rsp", NtruLPRimeParameters.ntrulpr653 },
            { "addEncap761.rsp", NtruLPRimeParameters.ntrulpr761 },
            { "addEncap857.rsp", NtruLPRimeParameters.ntrulpr857 },
            { "addEncap953.rsp", NtruLPRimeParameters.ntrulpr953 },
            { "addEncap1013.rsp", NtruLPRimeParameters.ntrulpr1013 },
            { "addEncap1277.rsp", NtruLPRimeParameters.ntrulpr1277 },
        };
        private static readonly List<string> LPREncapTestVectorFileNames = new List<string>(LPREncapTestVectors.Keys);

        private static readonly Dictionary<string, NtruLPRimeParameters> LPRDecapTestVectors = new Dictionary<string, NtruLPRimeParameters>()
        {
            { "addDecap653.rsp", NtruLPRimeParameters.ntrulpr653 },
            { "addDecap761.rsp", NtruLPRimeParameters.ntrulpr761 },
            { "addDecap857.rsp", NtruLPRimeParameters.ntrulpr857 },
            { "addDecap953.rsp", NtruLPRimeParameters.ntrulpr953 },
            { "addDecap1013.rsp", NtruLPRimeParameters.ntrulpr1013 },
            { "addDecap1277.rsp", NtruLPRimeParameters.ntrulpr1277 },
        };
        private static readonly List<string> LPRDecapTestVectorFileNames = new List<string>(LPRDecapTestVectors.Keys);

        [TestCaseSource(nameof(LPRaddRandTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntruprime.addRand.ntrulpr.",LPRFullTests,LPRaddRandTestVectors);
        }

        [TestCaseSource(nameof(LPREncapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestEncapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntruprime.encapTesting.ntrulpr.",LPREncapTests,LPREncapTestVectors);
        }

        [TestCaseSource(nameof(LPRDecapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestDecapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntruprime.decapTesting.ntrulpr.",LPRDecapTests,LPRDecapTestVectors);
        }
        
        private static void LPREncapTests(string name, IDictionary<string, string> buf,Dictionary<string, NtruLPRimeParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            NtruLPRimeParameters parameters = paramDict[name];

            NtruLPRimePublicKeyParameters publicKeyParams = new NtruLPRimePublicKeyParameters(parameters,expectedPK);

            NtruLPRimeKemGenerator encapsulationGenerator = new NtruLPRimeKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);
        }

        private static void LPRDecapTests(string name, IDictionary<string, string> buf,Dictionary<string, NtruLPRimeParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NtruLPRimeParameters parameters = paramDict[name];

            NtruLPRimePrivateKeyParameters privateKeyParams = new NtruLPRimePrivateKeyParameters(parameters,expectedSK);

            NtruLPRimeKemExtractor decapsulator = new NtruLPRimeKemExtractor(privateKeyParams);
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(expectedCT);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
        }

        private static void LPRFullTests(string name, IDictionary<string, string> buf,Dictionary<string, NtruLPRimeParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            
            NistSecureRandom random = new NistSecureRandom(seed, null);
            NtruLPRimeParameters parameters = paramDict[name];
            
            NtruLPRimeKeyPairGenerator keyGenerator = new NtruLPRimeKeyPairGenerator();
            NtruLPRimeKeyGenerationParameters generationParams = new NtruLPRimeKeyGenerationParameters(random,parameters);
            
            // Key Generation
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            
            NtruLPRimePublicKeyParameters publicKeyParams = (NtruLPRimePublicKeyParameters) keyPair.Public;
            NtruLPRimePrivateKeyParameters privateKeyParams = (NtruLPRimePrivateKeyParameters) keyPair.Private;

            // Encapsulation
            NtruLPRimeKemGenerator encapsulationGenerator = new NtruLPRimeKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
                
            // Decapsulation
            NtruLPRimeKemExtractor decapsulator = new NtruLPRimeKemExtractor(privateKeyParams);
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()), "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),"FAILED session int: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,NtruLPRimeParameters>> testFunc,Dictionary<string,NtruLPRimeParameters> parameters)
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
