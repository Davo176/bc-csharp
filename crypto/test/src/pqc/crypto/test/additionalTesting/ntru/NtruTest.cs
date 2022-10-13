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

        private static readonly Dictionary<string, NtruParameters> addRandTestVectors = new Dictionary<string, NtruParameters>()
        {
            { "addRand_935.rsp", NtruParameters.NtruHps2048509 },
            { "addRand_1234.rsp", NtruParameters.NtruHps2048677 },
            { "addRand_1590.rsp", NtruParameters.NtruHps4096821 },
            { "addRand_1450.rsp", NtruParameters.NtruHrss701 },
        };

        private static readonly List<string> addRandTestVectorFileNames = new List<string>(addRandTestVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntru.",FullTests,fullTestVectors);
        }

        [TestCaseSource(nameof(addRandTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddRandVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntru.addRand.",FullTests,addRandTestVectors);
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

        private static readonly Dictionary<string, NtruParameters> interopKgVectors = new Dictionary<string, NtruParameters>()
        {
             { "keypairs_csharp_935", NtruParameters.NtruHps2048509 },
             { "keypairs_csharp_1234", NtruParameters.NtruHps2048677 },
             { "keypairs_csharp_1590", NtruParameters.NtruHps4096821 },
             { "keypairs_csharp_1450", NtruParameters.NtruHrss701 }
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, NtruParameters> interopEncapVectors = new Dictionary<string, NtruParameters>()
        {
             { "keypairs_ref_935.rsp", NtruParameters.NtruHps2048509 },
             { "keypairs_ref_1234.rsp", NtruParameters.NtruHps2048677 },
             { "keypairs_ref_1590.rsp", NtruParameters.NtruHps4096821 },
             { "keypairs_ref_1450.rsp", NtruParameters.NtruHrss701 },
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, NtruParameters> interopDecapVectors = new Dictionary<string, NtruParameters>()
        {
             { "encapsulation_csharp_ref_935.rsp", NtruParameters.NtruHps2048509 },
             { "encapsulation_csharp_ref_1234.rsp", NtruParameters.NtruHps2048677 },
             { "encapsulation_csharp_ref_1590.rsp", NtruParameters.NtruHps4096821 },
             { "encapsulation_csharp_ref_1450.rsp", NtruParameters.NtruHrss701 },
        };
        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);

        [TestCaseSource(nameof(decapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestDecapVectors(string decapTestVectorFile)
        {
            RunTest(decapTestVectorFile,"pqc.ntru.decapTesting.",DecapTests,decapTestVectors);
        }

        [TestCaseSource(nameof(interopKgVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCreateKeypairs(string interopFile)
        {
            CreateKeypairs(interopFile,interopKgVectors);
        }

        [TestCaseSource(nameof(interopEncapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCreateEncaps(string interopFile)
        {
            RunTest(interopFile,"pqc.ntru.interoperability.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void checkDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.ntru.interoperability.",DecapTests,interopDecapVectors);
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
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

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

        public static void CreateKeypairs(string name,Dictionary<string, NtruParameters> paramDict){
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }
            byte[] personalisation = new byte[48];
            for (int i=48;i>0;i--){
                personalisation[48-i]=Convert.ToByte(i);
            }

            NistSecureRandom random = new NistSecureRandom(entropy_input, personalisation);
            NtruParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/ntru/interoperability/"+name+".rsp";

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                NtruKeyPairGenerator keysGenerator = new NtruKeyPairGenerator();
                NtruKeyGenerationParameters generationParams = new NtruKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                NtruPublicKeyParameters publicKeyParams = (NtruPublicKeyParameters)keys.Public;
                NtruPrivateKeyParameters privateKeyParams = (NtruPrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, NtruParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            NtruParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/ntru/interoperability/encapsulation_csharp_"+name.Substring("keypairs_ref_".Length,4)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            NtruPublicKeyParameters publicKeyParams = new NtruPublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            NtruKemGenerator encapsulationGenerator = new NtruKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
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
