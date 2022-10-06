using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Frodo;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class FrodoTest
    {
        private static readonly Dictionary<string, FrodoParameters> fullTestVectors = new Dictionary<string, FrodoParameters>()
        {
            { "PQCkemKAT_19888.rsp", FrodoParameters.frodokem19888r3 },
            { "PQCkemKAT_31296.rsp", FrodoParameters.frodokem31296r3 },
            { "PQCkemKAT_43088.rsp", FrodoParameters.frodokem43088r3 },
            { "PQCkemKAT_19888_shake.rsp", FrodoParameters.frodokem19888shaker3 },
            { "PQCkemKAT_31296_shake.rsp", FrodoParameters.frodokem31296shaker3 },
            { "PQCkemKAT_43088_shake.rsp", FrodoParameters.frodokem43088shaker3 },
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        private static readonly Dictionary<string, FrodoParameters> addRandTestVectors = new Dictionary<string, FrodoParameters>()
        {
            { "addRandTest_19888.rsp", FrodoParameters.frodokem19888r3 },
            { "addRandTest_31296.rsp", FrodoParameters.frodokem31296r3 },
            { "addRandTest_43088.rsp", FrodoParameters.frodokem43088r3 },
            { "addRandTest_shake_19888.rsp", FrodoParameters.frodokem19888shaker3 },
            { "addRandTest_shake_31296.rsp", FrodoParameters.frodokem31296shaker3 },
            { "addRandTest_shake_43088.rsp", FrodoParameters.frodokem43088shaker3 },
        };
        private static readonly List<string> addRandTestVectorFileNames = new List<string>(addRandTestVectors.Keys);

        private static readonly Dictionary<string, FrodoParameters> addEncapsTestVectors = new Dictionary<string, FrodoParameters>()
        {
            { "additionalEncaps_19888.rsp", FrodoParameters.frodokem19888r3 },
            { "additionalEncaps_31296.rsp", FrodoParameters.frodokem31296r3 },
            { "additionalEncaps_43088.rsp", FrodoParameters.frodokem43088r3 },
            { "additionalEncaps_shake_19888.rsp", FrodoParameters.frodokem19888shaker3 },
            { "additionalEncaps_shake_31296.rsp", FrodoParameters.frodokem31296shaker3 },
            { "additionalEncaps_shake_43088.rsp", FrodoParameters.frodokem43088shaker3 },
        };
        private static readonly List<string> addEncapsTestVectorFileNames = new List<string>(addEncapsTestVectors.Keys);

        private static readonly Dictionary<string, FrodoParameters> addDecapsTestVectors = new Dictionary<string, FrodoParameters>()
        {
            { "addDecapsTest_19888.rsp", FrodoParameters.frodokem19888r3 },
            { "addDecapsTest_31296.rsp", FrodoParameters.frodokem31296r3 },
            { "addDecapsTest_43088.rsp", FrodoParameters.frodokem43088r3 },
            { "addDecapsTest_shake_19888.rsp", FrodoParameters.frodokem19888shaker3 },
            { "addDecapsTest_shake_31296.rsp", FrodoParameters.frodokem31296shaker3 },
            { "addDecapsTest_shake_43088.rsp", FrodoParameters.frodokem43088shaker3 },
        };
        private static readonly List<string> addDecapsTestVectorFileNames = new List<string>(addDecapsTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.frodo.",FullTests,fullTestVectors);
        }

        [TestCaseSource(nameof(addRandTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddRandVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.frodo.addRandTest.",FullTests,addRandTestVectors);
        }

        [TestCaseSource(nameof(addEncapsTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddEncapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.frodo.addEncapsTest.",EncapTests,addEncapsTestVectors);
        }

        [TestCaseSource(nameof(addDecapsTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddDecapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.frodo.addDecapsTest.",DecapTests,addDecapsTestVectors);
        }

        private static void EncapTests(string name, IDictionary<string, string> buf,Dictionary<string, FrodoParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]); // seed for nist secure random
            byte[] pk = Hex.Decode(buf["pk"]);     // public key
            byte[] expectedCT = Hex.Decode(buf["ct"]);     // ciphertext
            byte[] expectedSS = Hex.Decode(buf["ss"]);     // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            FrodoParameters parameters = paramDict[name];

            FrodoPublicKeyParameters publicKeyParams = new FrodoPublicKeyParameters(parameters,pk);

            // Encapsulation
            FrodoKEMGenerator encapsulationGenerator = new FrodoKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            
            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, secret), "FAILED session enc: " + name + " " + count);
        }

        private static void DecapTests(string name, IDictionary<string, string> buf,Dictionary<string, FrodoParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]); // seed for nist secure random
            byte[] sk = Hex.Decode(buf["sk"]);     // private key
            byte[] ct = Hex.Decode(buf["ct"]);     // ciphertext
            byte[] expectedSS = Hex.Decode(buf["ss"]);     // session key

            FrodoParameters parameters = paramDict[name];

            FrodoPrivateKeyParameters privateKeyParams = new FrodoPrivateKeyParameters(parameters,sk);
            
            // Decapsulation
            FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privateKeyParams);
            byte[] decapsulatedSecret = frodoDecCipher.ExtractSecret(ct);

            Console.WriteLine(Hex.ToHexString(decapsulatedSecret));
            Console.WriteLine(Hex.ToHexString(expectedSS));

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, expectedSS),"FAILED session dec: " + name + " " + count);
        }


        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, FrodoParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]); // seed for nist secure random
            byte[] expectedPK = Hex.Decode(buf["pk"]);     // public key
            byte[] expectedSK = Hex.Decode(buf["sk"]);     // private key
            byte[] expectedCT = Hex.Decode(buf["ct"]);     // ciphertext
            byte[] expectedSS = Hex.Decode(buf["ss"]);     // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            FrodoParameters parameters = paramDict[name];

            FrodoKeyPairGenerator keyGenerator = new FrodoKeyPairGenerator();
            FrodoKeyGenerationParameters generationParams = new FrodoKeyGenerationParameters(random, parameters);

            // Key Generation

            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            FrodoPublicKeyParameters publicKeyParams = (FrodoPublicKeyParameters) keyPair.Public;
            FrodoPrivateKeyParameters privateKeyParams = (FrodoPrivateKeyParameters) keyPair.Private;

            // Encapsulation
            FrodoKEMGenerator encapsulationGenerator = new FrodoKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            
            // Decapsulation
            FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privateKeyParams);
            byte[] decapsulatedSecret = frodoDecCipher.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()), "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, secret), "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, expectedSS),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),"FAILED session int: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,FrodoParameters>> testFunc,Dictionary<string,FrodoParameters> parameters)
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
