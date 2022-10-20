using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Cmce;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class CmceTest
    {
        private static readonly Dictionary<string, CmceParameters> partialTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "3488-64-cmce.txt", CmceParameters.mceliece348864r3 },
            { "3488-64-f-cmce.txt", CmceParameters.mceliece348864fr3 },
            { "4608-96-cmce.txt", CmceParameters.mceliece460896r3 },
            { "4608-96-f-cmce.txt", CmceParameters.mceliece460896fr3 },
            { "6688-128-cmce.txt", CmceParameters.mceliece6688128r3 },
            { "6688-128-f-cmce.txt", CmceParameters.mceliece6688128fr3 },
            { "6960-119-cmce.txt", CmceParameters.mceliece6960119r3 },
            { "6960-119-f-cmce.txt", CmceParameters.mceliece6960119fr3 },
            { "8192-128-cmce.txt", CmceParameters.mceliece8192128r3 },
            { "8192-128-f-cmce.txt", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> partialTestVectorFileNames = new List<string>(partialTestVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> fullTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "348864cmce.rsp", CmceParameters.mceliece348864r3 },
            { "348864fcmce.rsp", CmceParameters.mceliece348864fr3 },
            { "460896cmce.rsp", CmceParameters.mceliece460896r3 },
            { "460896fcmce.rsp", CmceParameters.mceliece460896fr3 },
            { "6688128cmce.rsp", CmceParameters.mceliece6688128r3 },
            { "6688128fcmce.rsp", CmceParameters.mceliece6688128fr3 },
            { "6960119cmce.rsp", CmceParameters.mceliece6960119r3 },
            { "6960119fcmce.rsp", CmceParameters.mceliece6960119fr3 },
            { "8192128cmce.rsp", CmceParameters.mceliece8192128r3 },
            { "8192128fcmce.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> additionalTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "std.addRand_6492.rsp", CmceParameters.mceliece348864r3 }, 
            { "f.addRand_6492.rsp", CmceParameters.mceliece348864fr3 },
            { "std.addRand_13608.rsp", CmceParameters.mceliece460896r3 },
            { "f.addRand_13608.rsp", CmceParameters.mceliece460896fr3 },
            { "std.addRand_13932.rsp", CmceParameters.mceliece6688128r3 },
            { "f.addRand_13932.rsp", CmceParameters.mceliece6688128fr3 },
            { "std.addRand_13948.rsp", CmceParameters.mceliece6960119r3 },
            { "f.addRand_13948.rsp", CmceParameters.mceliece6960119fr3 },
            { "std.addRand_14120.rsp", CmceParameters.mceliece8192128r3 },
            { "f.addRand_14120.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> additionalTestVectorFileNames = new List<string>(additionalTestVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> additionalEncapTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "std.additionalEncapTesting_6492.rsp", CmceParameters.mceliece348864r3 }, 
            { "f.additionalEncapTesting_6492.rsp", CmceParameters.mceliece348864fr3 },
            { "std.additionalEncapTesting_13608.rsp", CmceParameters.mceliece460896r3 },
            { "f.additionalEncapTesting_13608.rsp", CmceParameters.mceliece460896fr3 },
            { "std.additionalEncapTesting_13932.rsp", CmceParameters.mceliece6688128r3 },
            { "f.additionalEncapTesting_13932.rsp", CmceParameters.mceliece6688128fr3 },
            { "std.additionalEncapTesting_13948.rsp", CmceParameters.mceliece6960119r3 },
            { "f.additionalEncapTesting_13948.rsp", CmceParameters.mceliece6960119fr3 },
            { "std.additionalEncapTesting_14120.rsp", CmceParameters.mceliece8192128r3 },
            { "f.additionalEncapTesting_14120.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> additionalEncapTestVectorFileNames = new List<string>(additionalEncapTestVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> additionalDecapTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "std.additionalDecapTesting_6492.rsp", CmceParameters.mceliece348864r3 }, 
            { "f.additionalDecapTesting_6492.rsp", CmceParameters.mceliece348864fr3 },
            { "std.additionalDecapTesting_13608.rsp", CmceParameters.mceliece460896r3 },
            { "f.additionalDecapTesting_13608.rsp", CmceParameters.mceliece460896fr3 },
            { "std.additionalDecapTesting_13932.rsp", CmceParameters.mceliece6688128r3 },
            { "f.additionalDecapTesting_13932.rsp", CmceParameters.mceliece6688128fr3 },
            { "std.additionalDecapTesting_13948.rsp", CmceParameters.mceliece6960119r3 },
            { "f.additionalDecapTesting_13948.rsp", CmceParameters.mceliece6960119fr3 },
            { "std.additionalDecapTesting_14120.rsp", CmceParameters.mceliece8192128r3 },
            { "f.additionalDecapTesting_14120.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> additionalDecapTestVectorFileNames = new List<string>(additionalDecapTestVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> createKPTestVectors = new Dictionary<string, CmceParameters>()
        {
            { "std/keypairs_csharp_6492.rsp", CmceParameters.mceliece348864r3 }, 
            { "f/keypairs_csharp_6492.rsp", CmceParameters.mceliece348864fr3 },
            { "std/keypairs_csharp_13608.rsp", CmceParameters.mceliece460896r3 },
            { "f/keypairs_csharp_13608.rsp", CmceParameters.mceliece460896fr3 },
            { "std/keypairs_csharp_13932.rsp", CmceParameters.mceliece6688128r3 },
            { "f/keypairs_csharp_13932.rsp", CmceParameters.mceliece6688128fr3 },
            { "std/keypairs_csharp_13948.rsp", CmceParameters.mceliece6960119r3 },
            { "f/keypairs_csharp_13948.rsp", CmceParameters.mceliece6960119fr3 },
            { "std/keypairs_csharp_14120.rsp", CmceParameters.mceliece8192128r3 },
            { "f/keypairs_csharp_14120.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> createKPTestVectorFileNames = new List<string>(createKPTestVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> interopEncapVectors = new Dictionary<string, CmceParameters>()
        {
            //{ "std.keypairs_ref_6492.rsp", CmceParameters.mceliece348864r3 }, 
            //{ "f.keypairs_ref_6492.rsp", CmceParameters.mceliece348864fr3 },
            { "std.keypairs_ref_13608.rsp", CmceParameters.mceliece460896r3 },
            { "f.keypairs_ref_13608.rsp", CmceParameters.mceliece460896fr3 },
            { "std.keypairs_ref_13932.rsp", CmceParameters.mceliece6688128r3 },
            { "f.keypairs_ref_13932.rsp", CmceParameters.mceliece6688128fr3 },
            { "std.keypairs_ref_13948.rsp", CmceParameters.mceliece6960119r3 },
            { "f.keypairs_ref_13948.rsp", CmceParameters.mceliece6960119fr3 },
            { "std.keypairs_ref_14120.rsp", CmceParameters.mceliece8192128r3 },
            { "f.keypairs_ref_14120.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, CmceParameters> interopDecapVectors = new Dictionary<string, CmceParameters>()
        {
            { "std.encapsulation_csharp_ref_6492.rsp", CmceParameters.mceliece348864r3 }, 
            { "f.encapsulation_csharp_ref_6492.rsp", CmceParameters.mceliece348864fr3 },
            { "std.encapsulation_csharp_ref_13608.rsp", CmceParameters.mceliece460896r3 },
            { "f.encapsulation_csharp_ref_13608.rsp", CmceParameters.mceliece460896fr3 },
            { "std.encapsulation_csharp_ref_13932.rsp", CmceParameters.mceliece6688128r3 },
            { "f.encapsulation_csharp_ref_13932.rsp", CmceParameters.mceliece6688128fr3 },
            { "std.encapsulation_csharp_ref_13948.rsp", CmceParameters.mceliece6960119r3 },
            { "f.encapsulation_csharp_ref_13948.rsp", CmceParameters.mceliece6960119fr3 },
            { "std.encapsulation_csharp_ref_14120.rsp", CmceParameters.mceliece8192128r3 },
            { "f.encapsulation_csharp_ref_14120.rsp", CmceParameters.mceliece8192128fr3 },
        };
        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);


        [TestCaseSource(nameof(partialTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestPartialVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.cmce.",FullTests,partialTestVectors);
        }

        // removed due to file size
        // [TestCaseSource(nameof(partialTestVectorFileNames))]
        // [Parallelizable(ParallelScope.All)]
        // public void TestFullVectors(string testVectorFile)
        // {
        //     RunTest(testVectorFile,"pqc.cmce.additionalTesting.full",FullTests,fullTestVectors);
        // }

        [TestCaseSource(nameof(additionalTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAdditionalVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.cmce.additionalTesting.interoperability.",FullTests,additionalTestVectors);
        }

        [TestCaseSource(nameof(additionalEncapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestEncapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.cmce.additionalTesting.interoperability.",EncapsTests,additionalEncapTestVectors);
        }

        [TestCaseSource(nameof(additionalDecapTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestDecapVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.cmce.additionalTesting.interoperability.",DecapsTest,additionalDecapTestVectors);
        }

        [TestCaseSource(nameof(createKPTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestCreateKPVectors(string testVectorFile)
        {
            CreateKeypairs(testVectorFile,createKPTestVectors);
        }

        [TestCaseSource(nameof(interopEncapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCreateEncaps(string interopFile)
        {
            RunTest(interopFile,"pqc.cmce.additionalTesting.interoperability.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCheckDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.cmce.additionalTesting.interoperability.",DecapsTest,interopDecapVectors);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, CmceParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            Console.Error.WriteLine(name + " " + count);

            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            CmceParameters parameters = paramDict[name];
            int dotIndex = name.IndexOf(".");
            String foldername = name.Substring(0,dotIndex);
            int underScoreIndex = name.LastIndexOf("_");
            String ending = name.Substring(underScoreIndex);



            //name.Substring(0,name.Length-"keypairs_ref_XX.rsp".Length-1)+"/encapsulated_csharp_"+name.Substring(name.IndexOf("csharp_"+"csharp_".Length),name.Length-name.IndexOf("csharp_"+"csharp_".Length))
            string f1 = "../../../data/pqc/cmce/additionalTesting/interoperability/"+foldername+"/encapsulated_csharp"+ending;
            Console.Error.WriteLine(f1);
            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            CmcePublicKeyParameters publicKeyParams = new CmcePublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            CmceKemGenerator encapsulationGenerator = new CmceKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
        }


        public static void CreateKeypairs(string name,Dictionary<string, CmceParameters> paramDict){
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
            CmceParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/cmce/additionalTesting/interoperability/"+name+"";

            string f1Contents = "";

            for (int i=0;i<10;i++){
                Console.Error.WriteLine(name + " " + i);
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                CmceKeyPairGenerator keysGenerator = new CmceKeyPairGenerator();
                CmceKeyGenerationParameters generationParams = new CmceKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                CmcePublicKeyParameters publicKeyParams = (CmcePublicKeyParameters)keys.Public;
                CmcePrivateKeyParameters privateKeyParams = (CmcePrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        
        private static void DecapsTest(string name, IDictionary<string, string> buf,Dictionary<string, CmceParameters> paramDict)
        {
            String count = buf["count"];
            byte[] expectedSK = Hex.Decode(buf["sk"]); 
            byte[] expectedCT = Hex.Decode(buf["ct"]); 
            byte[] expectedSS = Hex.Decode(buf["ss"]); 

            CmceParameters parameters = paramDict[name];

            CmcePrivateKeyParameters privateKeyParams = new CmcePrivateKeyParameters(parameters,expectedSK);

            // KEM Dec
            CmceKemExtractor decapsulator = new CmceKemExtractor(privateKeyParams);

            byte[] decapsulatedSecret = decapsulator.ExtractSecret(expectedCT);

            Assert.True(Arrays.AreEqual(decapsulatedSecret, 0, decapsulatedSecret.Length, expectedSS, 0, decapsulatedSecret.Length),"FAILED session dec: " + name + " " + count);            
        }

        private static void EncapsTests(string name, IDictionary<string, string> buf,Dictionary<string, CmceParameters> paramDict)
        {
             String count = buf["count"];

            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]); 
            byte[] expectedCT = Hex.Decode(buf["ct"]); 
            byte[] expectedSS = Hex.Decode(buf["ss"]); 

            NistSecureRandom random = new NistSecureRandom(seed, null);
            CmceParameters parameters = paramDict[name];

            // KEM Enc
            CmcePublicKeyParameters publicKeyParams = new CmcePublicKeyParameters(parameters,expectedPK);
            CmceKemGenerator encapsulationGenerator = new CmceKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),                        "FAILED cipher enc: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSS, 0, secret.Length, secret, 0, secret.Length),   "FAILED session enc: " + name + " " + count);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, CmceParameters> paramDict)
        {
            String count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedCT = Hex.Decode(buf["ct"]);
            byte[] expectedSS = Hex.Decode(buf["ss"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            CmceParameters parameters = paramDict[name];

            CmceKeyPairGenerator keysGenerator = new CmceKeyPairGenerator();
            CmceKeyGenerationParameters generationParams = new CmceKeyGenerationParameters(random, parameters);

            // Key Generation.

            keysGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

            CmcePublicKeyParameters publicKeyParams = (CmcePublicKeyParameters) keys.Public;
            CmcePrivateKeyParameters privateKeyParams = (CmcePrivateKeyParameters) keys.Private;

            
            // KEM Enc
            CmceKemGenerator encapsulationGenerator = new CmceKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            
            // KEM Dec
            CmceKemExtractor decapsulator = new CmceKemExtractor(privateKeyParams);

            byte[] decapsulatedSecret = decapsulator.ExtractSecret(generatedCipher);

            Assert.True(Arrays.AreEqual(expectedPK,  publicKeyParams.GetEncoded()),                "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()),                "FAILED secret key: " + name + " " + count);

            Assert.True(Arrays.AreEqual(expectedCT, generatedCipher),                               "FAILED cipher enc: " + name + " " + count);
            //Assert.AreEqual(decapsulatedSecret.Length * 8, parameters.DefaultKeySize);
            Assert.True(Arrays.AreEqual(secret, 0, secret.Length, expectedSS,0,secret.Length),"FAILED session dec: " + name + " " + count);
            Assert.True(Arrays.AreEqual(decapsulatedSecret,0, decapsulatedSecret.Length, secret,0, decapsulatedSecret.Length),                                "FAILED session enc: " + name + " " + count);
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,CmceParameters>> testFunc,Dictionary<string,CmceParameters> parameters)
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
