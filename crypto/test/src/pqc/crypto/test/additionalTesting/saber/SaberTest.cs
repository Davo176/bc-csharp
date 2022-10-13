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

        private static readonly Dictionary<string, SABERParameters> interopKgVectors = new Dictionary<string, SABERParameters>()
        {
             { "keypairs_csharp_1568", SABERParameters.lightsaberkem256r3 },
             { "keypairs_csharp_2304", SABERParameters.saberkem256r3 },
             { "keypairs_csharp_3040", SABERParameters.firesaberkem256r3 },
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, SABERParameters> interopEncapVectors = new Dictionary<string, SABERParameters>()
        {
             { "keypairs_ref_1568.rsp", SABERParameters.lightsaberkem256r3 },
             { "keypairs_ref_2304.rsp", SABERParameters.saberkem256r3 },
             { "keypairs_ref_3040.rsp", SABERParameters.firesaberkem256r3 },
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, SABERParameters> interopDecapVectors = new Dictionary<string, SABERParameters>()
        {
             { "encapsulation_csharp_ref_1568.rsp", SABERParameters.lightsaberkem256r3 },
             { "encapsulation_csharp_ref_2304.rsp", SABERParameters.saberkem256r3 },
             { "encapsulation_csharp_ref_3040.rsp", SABERParameters.firesaberkem256r3 },
        };
        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);

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
            RunTest(interopFile,"pqc.saber.interoperability.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void checkDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.saber.interoperability.",DecapTests,interopDecapVectors);
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

        public static void CreateKeypairs(string name,Dictionary<string, SABERParameters> paramDict){
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
            SABERParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/saber/interoperability/"+name+".rsp";

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                SABERKeyPairGenerator keysGenerator = new SABERKeyPairGenerator();
                SABERKeyGenerationParameters generationParams = new SABERKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                SABERPublicKeyParameters publicKeyParams = (SABERPublicKeyParameters)keys.Public;
                SABERPrivateKeyParameters privateKeyParams = (SABERPrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, SABERParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            SABERParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/saber/interoperability/encapsulation_csharp_"+name.Substring("keypairs_ref_".Length,4)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            SABERPublicKeyParameters publicKeyParams = new SABERPublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            SABERKEMGenerator encapsulationGenerator = new SABERKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
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
