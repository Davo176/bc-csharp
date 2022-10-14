using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Sike;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class SikeTests
    {
        private static readonly Dictionary<string, SIKEParameters> fullTestVectors = new Dictionary<string, SIKEParameters>()
        {
            { "PQCkemKAT_374.rsp" , SIKEParameters.sikep434 },
            { "PQCkemKAT_434.rsp" , SIKEParameters.sikep503 },
            { "PQCkemKAT_524.rsp" , SIKEParameters.sikep610 },
            { "PQCkemKAT_644.rsp" , SIKEParameters.sikep751 },
            { "PQCkemKAT_350.rsp" , SIKEParameters.sikep434_compressed },
            { "PQCkemKAT_407.rsp" , SIKEParameters.sikep503_compressed },
            { "PQCkemKAT_491.rsp" , SIKEParameters.sikep610_compressed },
            { "PQCkemKAT_602.rsp" , SIKEParameters.sikep751_compressed }
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        private static readonly Dictionary<string, SIKEParameters> addFullTestVectors = new Dictionary<string, SIKEParameters>()
        {
            { "addRandTest_374.rsp" , SIKEParameters.sikep434 },
            { "addRandTest_503.rsp" , SIKEParameters.sikep503 },
            { "addRandTest_610.rsp" , SIKEParameters.sikep610 },
            { "addRandTest_751.rsp" , SIKEParameters.sikep751 },
        };

        private static readonly List<string> fullAddTestVectorFileNames = new List<string>(addFullTestVectors.Keys);

        private static readonly Dictionary<string, SIKEParameters> interopKgVectors = new Dictionary<string, SIKEParameters>()
        {
             { "keypairs_csharp_374", SIKEParameters.sikep434 },
             { "keypairs_csharp_434", SIKEParameters.sikep503 },
             { "keypairs_csharp_524", SIKEParameters.sikep610 },
             { "keypairs_csharp_644", SIKEParameters.sikep751 },
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, SIKEParameters> interopEncapVectors = new Dictionary<string, SIKEParameters>()
        {
             { "keypairs_ref_374.rsp", SIKEParameters.sikep434 },
             { "keypairs_ref_434.rsp", SIKEParameters.sikep503 },
             { "keypairs_ref_524.rsp", SIKEParameters.sikep610 },
             { "keypairs_ref_644.rsp", SIKEParameters.sikep751 },
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, SIKEParameters> interopDecapVectors = new Dictionary<string, SIKEParameters>()
        {
             { "encapsulation_csharp_ref_374.rsp", SIKEParameters.sikep434 },
             { "encapsulation_csharp_ref_434.rsp", SIKEParameters.sikep503 },
             { "encapsulation_csharp_ref_524.rsp", SIKEParameters.sikep610 },
             { "encapsulation_csharp_ref_644.rsp", SIKEParameters.sikep751 },
        };
        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sike.",FullTests,fullTestVectors);
        }

        [TestCaseSource(nameof(fullAddTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sike.additionalRandomTesting.",FullTests,addFullTestVectors);
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
            RunTest(interopFile,"pqc.sike.interoperability.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void checkDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.sike.interoperability.",DecapTests,interopDecapVectors);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, SIKEParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);      // seed for SIKE secure random
            byte[] expectedPK = Hex.Decode(buf["pk"]);          // public key
            byte[] expectedSK = Hex.Decode(buf["sk"]);          // private key
            byte[] expectedCT = Hex.Decode(buf["ct"]);          // cipher text
            byte[] expectedSS = Hex.Decode(buf["ss"]);          // session key

            NistSecureRandom random = new NistSecureRandom(seed, null);
            SIKEParameters parameters = paramDict[name];

            SIKEKeyPairGenerator keyGenerator = new SIKEKeyPairGenerator();
            SIKEKeyGenerationParameters generationParams = new SIKEKeyGenerationParameters(random, parameters);


            // Key Generation
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            
            SIKEPublicKeyParameters publicKeyParams = (SIKEPublicKeyParameters) keyPair.Public;
            SIKEPrivateKeyParameters privateKeyParams = (SIKEPrivateKeyParameters)keyPair.Private;

            // Encapsulation
            SIKEKEMGenerator encapsulationGenerator = new SIKEKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            // KEM Dec
            SIKEKEMExtractor decapsulator = new SIKEKEMExtractor(privateKeyParams);
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()),"FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()),"FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),"FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, secret),   "FAILED session enc: " + name + " " + count);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, expectedSS),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, secret),"FAILED session int: " + name + " " + count);
        }

        private static void DecapTests(string name, IDictionary<string, string> buf,Dictionary<string, SIKEParameters> paramDict)
        {
            String count = buf["count"];
            byte[] expectedSK = Hex.Decode(buf["sk"]); // private key
            byte[] expectedCT = Hex.Decode(buf["ct"]); // ciphertext
            byte[] expectedSS = Hex.Decode(buf["ss"]); // session key

            SIKEParameters parameters = paramDict[name];
            // KEM Dec
            SIKEKEMExtractor decapsulator = new SIKEKEMExtractor(new SIKEPrivateKeyParameters(parameters,expectedSK));
 
            byte[] decapsulatedSecret = decapsulator.ExtractSecret(expectedCT);

            Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);
        }

        public static void CreateKeypairs(string name,Dictionary<string, SIKEParameters> paramDict){
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
            SIKEParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/sike/interoperability/"+name+".rsp";

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                SIKEKeyPairGenerator keysGenerator = new SIKEKeyPairGenerator();
                SIKEKeyGenerationParameters generationParams = new SIKEKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                SIKEPublicKeyParameters publicKeyParams = (SIKEPublicKeyParameters)keys.Public;
                SIKEPrivateKeyParameters privateKeyParams = (SIKEPrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, SIKEParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            SIKEParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/sike/interoperability/encapsulation_csharp_"+name.Substring("keypairs_ref_".Length,3)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            SIKEPublicKeyParameters publicKeyParams = new SIKEPublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            SIKEKEMGenerator encapsulationGenerator = new SIKEKEMGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,SIKEParameters>> testFunc,Dictionary<string,SIKEParameters> parameters)
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
