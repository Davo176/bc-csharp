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
            { "addRand1277.rsp", NtruLPRimeParameters.ntrulpr1277 },
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

        private static readonly Dictionary<string, NtruLPRimeParameters> interopKgVectors = new Dictionary<string, NtruLPRimeParameters>()
        {
             { "keypairs_csharp_1125", NtruLPRimeParameters.ntrulpr653 },
             { "keypairs_csharp_1294", NtruLPRimeParameters.ntrulpr761 },
             { "keypairs_csharp_1463", NtruLPRimeParameters.ntrulpr857 },
             { "keypairs_csharp_1652", NtruLPRimeParameters.ntrulpr953 },
             { "keypairs_csharp_1773", NtruLPRimeParameters.ntrulpr1013 },
             { "keypairs_csharp_2231", NtruLPRimeParameters.ntrulpr1277 },
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, NtruLPRimeParameters> interopEncapVectors = new Dictionary<string, NtruLPRimeParameters>()
        {
             { "keypairs_ref_1125.rsp", NtruLPRimeParameters.ntrulpr653 },
             { "keypairs_ref_1294.rsp", NtruLPRimeParameters.ntrulpr761 },
             { "keypairs_ref_1463.rsp", NtruLPRimeParameters.ntrulpr857 },
             { "keypairs_ref_1652.rsp", NtruLPRimeParameters.ntrulpr953 },
             { "keypairs_ref_1773.rsp", NtruLPRimeParameters.ntrulpr1013 },
             { "keypairs_ref_2231.rsp", NtruLPRimeParameters.ntrulpr1277 },
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, NtruLPRimeParameters> interopDecapVectors = new Dictionary<string, NtruLPRimeParameters>()
        {
             { "encapsulation_csharp_ref_1125.rsp", NtruLPRimeParameters.ntrulpr653 },
             { "encapsulation_csharp_ref_1294.rsp", NtruLPRimeParameters.ntrulpr761 },
             { "encapsulation_csharp_ref_1463.rsp", NtruLPRimeParameters.ntrulpr857 },
             { "encapsulation_csharp_ref_1652.rsp", NtruLPRimeParameters.ntrulpr953 },
             { "encapsulation_csharp_ref_1773.rsp", NtruLPRimeParameters.ntrulpr1013 },
             { "encapsulation_csharp_ref_2231.rsp", NtruLPRimeParameters.ntrulpr1277 },
        };
        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);

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
            RunTest(interopFile,"pqc.ntruprime.interoperability.ntrulpr.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void checkDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.ntruprime.interoperability.ntrulpr.",LPRDecapTests,interopDecapVectors);
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

        public static void CreateKeypairs(string name,Dictionary<string, NtruLPRimeParameters> paramDict){
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
            NtruLPRimeParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/ntruprime/interoperability/ntrulpr/"+name+".rsp";

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                NtruLPRimeKeyPairGenerator keysGenerator = new NtruLPRimeKeyPairGenerator();
                NtruLPRimeKeyGenerationParameters generationParams = new NtruLPRimeKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                NtruLPRimePublicKeyParameters publicKeyParams = (NtruLPRimePublicKeyParameters)keys.Public;
                NtruLPRimePrivateKeyParameters privateKeyParams = (NtruLPRimePrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, NtruLPRimeParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            NtruLPRimeParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/ntruprime/interoperability/ntrulpr/encapsulation_csharp_"+name.Substring("keypairs_ref_".Length,4)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            NtruLPRimePublicKeyParameters publicKeyParams = new NtruLPRimePublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            NtruLPRimeKemGenerator encapsulationGenerator = new NtruLPRimeKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
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
