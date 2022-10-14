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

        private static readonly Dictionary<string, FrodoParameters> interopKgVectors = new Dictionary<string, FrodoParameters>()
        {
             { "keypairs_csharp_19888", FrodoParameters.frodokem19888r3 },
             { "keypairs_csharp_31296", FrodoParameters.frodokem31296r3 },
             { "keypairs_csharp_43088", FrodoParameters.frodokem43088r3 }
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, FrodoParameters> interopEncapVectors = new Dictionary<string, FrodoParameters>()
        {
             { "keypairs_ref_19888.rsp", FrodoParameters.frodokem19888r3 },
             { "keypairs_ref_31296.rsp", FrodoParameters.frodokem31296r3 },
             { "keypairs_ref_43088.rsp", FrodoParameters.frodokem43088r3 },
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, FrodoParameters> interopDecapVectors = new Dictionary<string, FrodoParameters>()
        {
             { "encapsulation_csharp_ref_19888.rsp", FrodoParameters.frodokem19888r3 },
             { "encapsulation_csharp_ref_31296.rsp", FrodoParameters.frodokem31296r3 },
             { "encapsulation_csharp_ref_43088.rsp", FrodoParameters.frodokem43088r3 }
        };
        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);

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
            RunTest(interopFile,"pqc.frodo.interoperability.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void checkDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.frodo.interoperability.",DecapTests,interopDecapVectors);
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
            byte[] sk = Hex.Decode(buf["sk"]);     // private key
            byte[] ct = Hex.Decode(buf["ct"]);     // ciphertext
            byte[] expectedSS = Hex.Decode(buf["ss"]);     // session key

            FrodoParameters parameters = paramDict[name];

            FrodoPrivateKeyParameters privateKeyParams = new FrodoPrivateKeyParameters(parameters,sk);
            
            // Decapsulation
            FrodoKEMExtractor frodoDecCipher = new FrodoKEMExtractor(privateKeyParams);
            byte[] decapsulatedSecret = frodoDecCipher.ExtractSecret(ct);

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

        public static void CreateKeypairs(string name,Dictionary<string, FrodoParameters> paramDict){
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
            FrodoParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/frodo/interoperability/"+name+".rsp";

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                FrodoKeyPairGenerator keysGenerator = new FrodoKeyPairGenerator();
                FrodoKeyGenerationParameters generationParams = new FrodoKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                FrodoPublicKeyParameters publicKeyParams = (FrodoPublicKeyParameters)keys.Public;
                FrodoPrivateKeyParameters privateKeyParams = (FrodoPrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, FrodoParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            FrodoParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/frodo/interoperability/encapsulation_csharp_"+name.Substring("keypairs_ref_".Length,5)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            FrodoPublicKeyParameters publicKeyParams = new FrodoPublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            FrodoKEMGenerator encapsulationGenerator = new FrodoKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
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
