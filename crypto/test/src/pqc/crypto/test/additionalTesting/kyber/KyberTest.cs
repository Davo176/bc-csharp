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
        private static readonly Dictionary<string, KyberParameters> addRandVectors = new Dictionary<string, KyberParameters>()
        {
             { "addRand_1632.rsp", KyberParameters.kyber512 },
             { "addRand_2400.rsp", KyberParameters.kyber768 },
             { "addRand_3168.rsp", KyberParameters.kyber1024 }
        };
        private static readonly List<string> addRandVectorsFileNames = new List<string>(addRandVectors.Keys);

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

        private static readonly Dictionary<string, KyberParameters> interopKgVectors = new Dictionary<string, KyberParameters>()
        {
             { "keypairs_csharp_1632", KyberParameters.kyber512 },
             { "keypairs_csharp_2400", KyberParameters.kyber768 },
             { "keypairs_csharp_3168", KyberParameters.kyber1024 }
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, KyberParameters> interopEncapVectors = new Dictionary<string, KyberParameters>()
        {
             { "keypairs_ref_1632.rsp", KyberParameters.kyber512 },
             { "keypairs_ref_2400.rsp", KyberParameters.kyber768 },
             { "keypairs_ref_3168.rsp", KyberParameters.kyber1024 }
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, KyberParameters> interopDecapVectors = new Dictionary<string, KyberParameters>()
        {
             { "encapsulation_csharp_ref_1632.rsp", KyberParameters.kyber512 },
             { "encapsulation_csharp_ref_2400.rsp", KyberParameters.kyber768 },
             { "encapsulation_csharp_ref_3168.rsp", KyberParameters.kyber1024 }
        };
        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);


        [TestCaseSource(nameof(addRandVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.crystals.kyber.addRand.",FullTests,addRandVectors);
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
            RunTest(interopFile,"pqc.crystals.kyber.interoperability.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCreateDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.crystals.kyber.interoperability.",testDecap,interopDecapVectors);
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
            KyberKemGenerator encapsulationGenerator = new KyberKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),                        "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length),   "FAILED session enc: " + name + " " + count);
        }
        private static void testDecap(string name, IDictionary<string, string> buf,Dictionary<string, KyberParameters> paramDict)
        {
            String count = buf["count"];
            byte[] expectedSK = Hex.Decode(buf["sk"]); 
            byte[] expectedCT = Hex.Decode(buf["ct"]); 
            byte[] expectedSS = Hex.Decode(buf["ss"]); 

            KyberParameters parameters = paramDict[name];

            KyberPrivateKeyParameters privateKeyParams = new KyberPrivateKeyParameters(parameters,expectedSK);

            // KEM Dec
            KyberKemExtractor decapsulator = new KyberKemExtractor(privateKeyParams);

            byte[] decapsulatedSecret = decapsulator.ExtractSecret(expectedCT);

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
            KyberKemGenerator encapsulationGenerator = new KyberKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            
            // Decapsulation
            KyberKemExtractor decapsulator = new KyberKemExtractor(privateKeyParams);

            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()),                "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()),                "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),                        "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length),   "FAILED session enc: " + name + " " + count);

            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),                                          "FAILED session int: " + name + " " + count);
        }

        public static void CreateKeypairs(string name,Dictionary<string, KyberParameters> paramDict){
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
            KyberParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/crystals/kyber/interoperability/"+name+".rsp";

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                KyberKeyPairGenerator keysGenerator = new KyberKeyPairGenerator();
                KyberKeyGenerationParameters generationParams = new KyberKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                KyberPublicKeyParameters publicKeyParams = (KyberPublicKeyParameters)keys.Public;
                KyberPrivateKeyParameters privateKeyParams = (KyberPrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, KyberParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            KyberParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/crystals/kyber/interoperability/encapsulation_csharp_"+name.Substring("keypairs_ref_".Length,4)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            KyberPublicKeyParameters publicKeyParams = new KyberPublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            KyberKemGenerator encapsulationGenerator = new KyberKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
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
