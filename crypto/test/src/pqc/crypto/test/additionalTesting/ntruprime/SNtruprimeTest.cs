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
        private static readonly Dictionary<string, SNtruPrimeParameters> SNtruaddRandTestVectors = new Dictionary<string, SNtruPrimeParameters>()
        {
            { "addRand653.rsp", SNtruPrimeParameters.sntrup653 },
            { "addRand761.rsp", SNtruPrimeParameters.sntrup761 },
            { "addRand857.rsp", SNtruPrimeParameters.sntrup857 },
            { "addRand953.rsp", SNtruPrimeParameters.sntrup953 },
            { "addRand1013.rsp", SNtruPrimeParameters.sntrup1013 },
            { "addRand1277.rsp", SNtruPrimeParameters.sntrup1277 },
        };
        private static readonly List<string> SNtruaddRandTestVectorFileNames = new List<string>(SNtruaddRandTestVectors.Keys);

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

        private static readonly Dictionary<string, SNtruPrimeParameters> interopKgVectors = new Dictionary<string, SNtruPrimeParameters>()
        {
             { "keypairs_csharp_1518", SNtruPrimeParameters.sntrup653 },
             { "keypairs_csharp_1763", SNtruPrimeParameters.sntrup761 },
             { "keypairs_csharp_1999", SNtruPrimeParameters.sntrup857 },
             { "keypairs_csharp_2254", SNtruPrimeParameters.sntrup953 },
             { "keypairs_csharp_2417", SNtruPrimeParameters.sntrup1013 },
             { "keypairs_csharp_3059", SNtruPrimeParameters.sntrup1277 },
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, SNtruPrimeParameters> interopEncapVectors = new Dictionary<string, SNtruPrimeParameters>()
        {
             { "keypairs_ref_1518.rsp", SNtruPrimeParameters.sntrup653 },
             { "keypairs_ref_1763.rsp", SNtruPrimeParameters.sntrup761 },
             { "keypairs_ref_1999.rsp", SNtruPrimeParameters.sntrup857 },
             { "keypairs_ref_2254.rsp", SNtruPrimeParameters.sntrup953 },
             { "keypairs_ref_2417.rsp", SNtruPrimeParameters.sntrup1013 },
             { "keypairs_ref_3059.rsp", SNtruPrimeParameters.sntrup1277 },
        };
        private static readonly List<string> interopEncapVectorsFileNames = new List<string>(interopEncapVectors.Keys);

        private static readonly Dictionary<string, SNtruPrimeParameters> interopDecapVectors = new Dictionary<string, SNtruPrimeParameters>()
        {
             { "encapsulation_csharp_ref_1518.rsp", SNtruPrimeParameters.sntrup653 },
             { "encapsulation_csharp_ref_1763.rsp", SNtruPrimeParameters.sntrup761 },
             { "encapsulation_csharp_ref_1999.rsp", SNtruPrimeParameters.sntrup857 },
             { "encapsulation_csharp_ref_2254.rsp", SNtruPrimeParameters.sntrup953 },
             { "encapsulation_csharp_ref_2417.rsp", SNtruPrimeParameters.sntrup1013 },
             { "encapsulation_csharp_ref_3059.rsp", SNtruPrimeParameters.sntrup1277 },
        };

        private static readonly List<string> interopDecapVectorsFileNames = new List<string>(interopDecapVectors.Keys);


        [TestCaseSource(nameof(SNtruaddRandTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.ntruprime.addRand.sntru.",SNtruFullTests,SNtruaddRandTestVectors);
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
            RunTest(interopFile,"pqc.ntruprime.interoperability.sntru.",CreateEncaps,interopEncapVectors);
        }

        [TestCaseSource(nameof(interopDecapVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void checkDecaps(string interopFile)
        {
            RunTest(interopFile,"pqc.ntruprime.interoperability.sntru.",SNtruDecapTests,interopDecapVectors);
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

        public static void CreateKeypairs(string name,Dictionary<string, SNtruPrimeParameters> paramDict){
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
            SNtruPrimeParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/ntruprime/interoperability/sntru/"+name+".rsp";

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                SNtruPrimeKeyPairGenerator keysGenerator = new SNtruPrimeKeyPairGenerator();
                SNtruPrimeKeyGenerationParameters generationParams = new SNtruPrimeKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();

                SNtruPrimePublicKeyParameters publicKeyParams = (SNtruPrimePublicKeyParameters)keys.Public;
                SNtruPrimePrivateKeyParameters privateKeyParams = (SNtruPrimePrivateKeyParameters)keys.Private;
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateEncaps(string name, IDictionary<string, string> buf,Dictionary<string, SNtruPrimeParameters> paramDict){
            String count = buf["count"];
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            SNtruPrimeParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/ntruprime/interoperability/sntru/encapsulation_csharp_"+name.Substring("keypairs_ref_".Length,4)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            
            SNtruPrimePublicKeyParameters publicKeyParams = new SNtruPrimePublicKeyParameters(parameters,expectedPK);
            f1Contents += "pk = " + buf["pk"] + "\n";
            f1Contents += "sk = " + buf["sk"] + "\n";
            SNtruPrimeKemGenerator encapsulationGenerator = new SNtruPrimeKemGenerator(random);
            ISecretWithEncapsulation encapsulatedSecret = encapsulationGenerator.GenerateEncapsulated(publicKeyParams);
            byte[] generatedCipher = encapsulatedSecret.GetEncapsulation();
            byte[] secret = encapsulatedSecret.GetSecret();
            f1Contents += "ct = " + Hex.ToHexString(generatedCipher) + "\n";
            f1Contents += "ss = " + Hex.ToHexString(secret) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
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
