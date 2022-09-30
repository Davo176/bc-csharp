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
    public class SNTRUPrimeTest
    {
        private static readonly Dictionary<string, SNtruPrimeParameters> SNtrufullTestVectors = new Dictionary<string, SNtruPrimeParameters>()
        {
            { "kat_kem_sntrup_653.rsp", SNtruPrimeParameters.sntrup653 },
            { "kat_kem_sntrup_761.rsp", SNtruPrimeParameters.sntrup761 },
            { "kat_kem_sntrup_857.rsp", SNtruPrimeParameters.sntrup857 },
            { "kat_kem_sntrup_953.rsp", SNtruPrimeParameters.sntrup953 },
            { "kat_kem_sntrup_1013.rsp", SNtruPrimeParameters.sntrup1013 },
            { "kat_kem_sntrup_1277.rsp", SNtruPrimeParameters.sntrup1277 },
        };
        private static readonly List<string> SNtrufullTestVectorFileNames = new List<string>(SNtrufullTestVectors.Keys);

        private static readonly Dictionary<string, SNtruPrimeParameters> SNtruEncapTestVectors = new Dictionary<string, SNtruPrimeParameters>()
        {
            { "addEncap653.rsp", SNtruPrimeParameters.sntrup653 },
            { "addEncap761.rsp", SNtruPrimeParameters.sntrup761 },
            { "addEncap857.rsp", SNtruPrimeParameters.sntrup857 },
            { "addEncap953.rsp", SNtruPrimeParameters.sntrup953 },
            { "addEncap1013.rsp", SNtruPrimeParameters.sntrup1013 },
            { "addEncap1277.rsp", SNtruPrimeParameters.sntrup1277 },
        };
        private static readonly List<string> SNtruEncapTestVectorFileNames = new List<string>(SNtruEncapTestVectors.Keys);

        private static readonly Dictionary<string, SNtruPrimeParameters> SNtruDecapTestVectors = new Dictionary<string, SNtruPrimeParameters>()
        {
            { "addDecap653.rsp", SNtruPrimeParameters.sntrup653 },
            { "addDecap761.rsp", SNtruPrimeParameters.sntrup761 },
            { "addDecap857.rsp", SNtruPrimeParameters.sntrup857 },
            { "addDecap953.rsp", SNtruPrimeParameters.sntrup953 },
            { "addDecap1013.rsp", SNtruPrimeParameters.sntrup1013 },
            { "addDecap1277.rsp", SNtruPrimeParameters.sntrup1277 },
        };
        private static readonly List<string> SNtruDecapTestVectorFileNames = new List<string>(SNtruDecapTestVectors.Keys);

        [TestCaseSource(nameof(SNtrufullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntruprime.",SNtruFullTests,SNtrufullTestVectors);
        }

        [TestCaseSource(nameof(SNtruEncapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestEncapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntruprime.encapTesting.sntru.",SNtruEncapTests,SNtruEncapTestVectors);
        }

        [TestCaseSource(nameof(SNtruDecapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestDecapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntruprime.decapTesting.sntru.",SNtruDecapTests,SNtruDecapTestVectors);
        }

        private static void SNtruEncapTests(string name, IDictionary<string, string> buf,Dictionary<string, SNtruPrimeParameters> paramDict)
        {
            String count = buf["count"];   
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);


            NistSecureRandom random = new NistSecureRandom(seed, null);
            SNtruPrimeParameters parameters = paramDict[name];

            SNtruPrimePublicKeyParameters publicKeyParams = new SNtruPrimePublicKeyParameters(parameters,pk);

            // Encapsulation
            SNtruPrimeKemGenerator encapsulationGenerator = new SNtruPrimeKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);
        }

        private static void SNtruDecapTests(string name, IDictionary<string, string> buf,Dictionary<string, SNtruPrimeParameters> paramDict)
        {
            String count = buf["count"];   
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] ct = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            SNtruPrimeParameters parameters = paramDict[name];
          
            SNtruPrimePrivateKeyParameters privateKeyParams = new SNtruPrimePrivateKeyParameters(parameters, sk);

            // Decapsulation
            SNtruPrimeKemExtractor ntruDecCipher = new SNtruPrimeKemExtractor(privateKeyParams);
            byte[] decapsulatedSecret = ntruDecCipher.ExtractSecret(ct);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
        }

        private static void SNtruFullTests(string name, IDictionary<string, string> buf,Dictionary<string, SNtruPrimeParameters> paramDict)
        {
            String count = buf["count"];   
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);


            NistSecureRandom random = new NistSecureRandom(seed, null);
            SNtruPrimeParameters parameters = paramDict[name];

            SNtruPrimeKeyPairGenerator keyGenerator = new SNtruPrimeKeyPairGenerator();
            SNtruPrimeKeyGenerationParameters generationParams = new SNtruPrimeKeyGenerationParameters(random, parameters);

            // Generate the key pair
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            SNtruPrimePublicKeyParameters publicKeyParams = (SNtruPrimePublicKeyParameters)keyPair.Public;
            SNtruPrimePrivateKeyParameters privateKeyParams = (SNtruPrimePrivateKeyParameters)keyPair.Private;

            // Encapsulation
            SNtruPrimeKemGenerator encapsulationGenerator = new SNtruPrimeKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            // Decapsulation
            SNtruPrimeKemExtractor ntruDecCipher = new SNtruPrimeKemExtractor(privateKeyParams);
            byte[] decapsulatedSecret = ntruDecCipher.ExtractSecret(generatedCipher);


            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()), "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher), "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length), "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),"FAILED session int: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,SNtruPrimeParameters>> testFunc,Dictionary<string,SNtruPrimeParameters> parameters)
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
