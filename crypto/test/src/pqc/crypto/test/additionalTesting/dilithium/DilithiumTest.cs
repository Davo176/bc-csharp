using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class DilithiumTest
    {
        private static readonly Dictionary<string, DilithiumParameters> addRandTestVectors = new Dictionary<string, DilithiumParameters>()
        {
            { "addRand_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
            { "addRand_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
            { "addRand_Dilithium5.rsp", DilithiumParameters.Dilithium5 }
        };
        private static readonly List<string> addRandTestVectorFileNames = new List<string>(addRandTestVectors.Keys);

        private static readonly Dictionary<string, DilithiumParameters> signTestVectors = new Dictionary<string, DilithiumParameters>()
        {
            { "addSignTest_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
            { "addSignTest_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
            { "addSignTest_Dilithium5.rsp", DilithiumParameters.Dilithium5 }
        };

        private static readonly List<string> signTestVectorFileNames = new List<string>(signTestVectors.Keys);

        private static readonly Dictionary<string, DilithiumParameters> interopKgVectors = new Dictionary<string, DilithiumParameters>()
        {
             { "keypairs_csharp_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
             { "keypairs_csharp_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
             { "keypairs_csharp_Dilithium5.rsp", DilithiumParameters.Dilithium5 }
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, DilithiumParameters> interopSignedVectors = new Dictionary<string, DilithiumParameters>()
        {
             { "keypairs_ref_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
             { "keypairs_ref_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
             { "keypairs_ref_Dilithium5.rsp", DilithiumParameters.Dilithium5 },
        };
        private static readonly List<string> interopSignedVectorsFileNames = new List<string>(interopSignedVectors.Keys);

        private static readonly Dictionary<string, DilithiumParameters> interopCheckSignedVectors = new Dictionary<string, DilithiumParameters>()
        {
             { "signed_csharp_ref_Dilithium2.rsp", DilithiumParameters.Dilithium2 },
             { "signed_csharp_ref_Dilithium3.rsp", DilithiumParameters.Dilithium3 },
             { "signed_csharp_ref_Dilithium5.rsp", DilithiumParameters.Dilithium5 },
        };
        private static readonly List<string> interopCheckSignedVectorsFileNames = new List<string>(interopCheckSignedVectors.Keys);


        [TestCaseSource(nameof(addRandTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.crystals.dilithium.addRand.",FullTests,addRandTestVectors);
        }

        [TestCaseSource(nameof(signTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestSignVectors(string signTestVectorFile)
        {
            RunTest(signTestVectorFile,"pqc.crystals.dilithium.signVectors.",testSign,signTestVectors);
        }

        [TestCaseSource(nameof(interopKgVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCreateKeypairs(string interopFile)
        {
            CreateKeypairs(interopFile,interopKgVectors);
        }

        [TestCaseSource(nameof(interopSignedVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCreateSigned(string interopFile)
        {
            RunTest(interopFile,"pqc.crystals.dilithium.interoperability.",CreateSigned,interopSignedVectors);
        }

        [TestCaseSource(nameof(interopCheckSignedVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCheckSigned(string interopFile)
        {
            RunTest(interopFile,"pqc.crystals.dilithium.interoperability.",CheckSigned,interopCheckSignedVectors);
        }



        private static void testSign(string name, IDictionary<string, string> buf,Dictionary<string, DilithiumParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            int mlen = int.Parse(buf["mlen"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            int expectedSMLEN = int.Parse(buf["smlen"]);
            byte[] expectedSM = Hex.Decode(buf["sm"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            DilithiumParameters parameters = paramDict[name];

            DilithiumSigner signer = new DilithiumSigner();
            DilithiumPrivateKeyParameters privateKeyParams = new DilithiumPrivateKeyParameters(parameters,expectedSK,random);

            signer.Init(true, privateKeyParams);
            byte[] generatedSM = signer.GenerateSignature(msg);
            byte[] finalSM = Arrays.ConcatenateAll(generatedSM, msg);

            Assert.True(expectedSMLEN == finalSM.Length, "FAILED signature length: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSM, finalSM), "FAILED signature gen: " + name + " " + count);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, DilithiumParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            int mlen = int.Parse(buf["mlen"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            int expectedSMLEN = int.Parse(buf["smlen"]);
            byte[] expectedSM = Hex.Decode(buf["sm"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            DilithiumParameters parameters = paramDict[name];

            DilithiumKeyPairGenerator keyGenerator = new DilithiumKeyPairGenerator();
            DilithiumKeyGenerationParameters generationParams = new DilithiumKeyGenerationParameters(random, parameters);

            // Key Generation
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            DilithiumPublicKeyParameters publicKeyParams = (DilithiumPublicKeyParameters) keyPair.Public;
            DilithiumPrivateKeyParameters privateKeyParams = (DilithiumPrivateKeyParameters) keyPair.Private;

            // Sign
            DilithiumSigner signer = new DilithiumSigner();

            signer.Init(true, privateKeyParams);
            byte[] generatedSM = signer.GenerateSignature(msg);
            byte[] finalSM = Arrays.ConcatenateAll(generatedSM, msg);

            // Verify
            signer.Init(false, publicKeyParams);
            Boolean validSignature = signer.VerifySignature(msg, generatedSM);

            Assert.True(Arrays.AreEqual(expectedPK, publicKeyParams.GetEncoded()), "FAILED public key: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), "FAILED secret key: " + name + " " + count);

            Assert.True(expectedSMLEN == finalSM.Length, "FAILED signature length: " + name + " " + count);
            Assert.True(Arrays.AreEqual(expectedSM, finalSM), "FAILED signature gen: " + name + " " + count);

            Assert.True(validSignature, "FAILED signature verify: " + name + " " + count);
        }

        public static void CreateKeypairs(string name,Dictionary<string, DilithiumParameters> paramDict){
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
            DilithiumParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/crystals/dilithium/interoperability/"+name;

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                int messageLength = 33*(i+1);
                byte[] message = new byte[messageLength];
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                DilithiumKeyPairGenerator keysGenerator = new DilithiumKeyPairGenerator();
                DilithiumKeyGenerationParameters generationParams = new DilithiumKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();
                random.NextBytes(message,0,messageLength);

                DilithiumPublicKeyParameters publicKeyParams = (DilithiumPublicKeyParameters)keys.Public;
                DilithiumPrivateKeyParameters privateKeyParams = (DilithiumPrivateKeyParameters)keys.Private;
                f1Contents += "mlen = " + messageLength.ToString()+"\n";
                f1Contents += "msg = " + Hex.ToHexString(message)+"\n";
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateSigned(string name, IDictionary<string, string> buf,Dictionary<string, DilithiumParameters> paramDict){
            String count = buf["count"];
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] message = Hex.Decode(buf["msg"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            DilithiumParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/crystals/dilithium/interoperability/signed_csharp_"+name.Substring("keypairs_ref_".Length,"Dilithium2".Length)+".rsp";

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            f1Contents += "pk = "+buf["pk"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);

            DilithiumPrivateKeyParameters privateKeyParams = new DilithiumPrivateKeyParameters(parameters,sk,random);
            DilithiumSigner signer = new DilithiumSigner();

            signer.Init(true,privateKeyParams);
            
            byte[] sigGenerated = signer.GenerateSignature(message);
            byte[] attachedSig = Arrays.Concatenate(sigGenerated,message);
            f1Contents += "mlen = " + buf["mlen"] + "\n";
            f1Contents += "msg = " + buf["msg"] + "\n";
            f1Contents += "smlen = " + attachedSig.Length.ToString() + "\n";
            f1Contents += "sm = " + Hex.ToHexString(attachedSig) + "\n";
            
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
        }

        public static void CheckSigned(string name, IDictionary<string, string> buf,Dictionary<string, DilithiumParameters> paramDict){
            String count = buf["count"];
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] message = Hex.Decode(buf["msg"]);
            byte[] sm = Hex.Decode(buf["sm"]);
            int smlen = int.Parse(buf["smlen"]);
            int mlen = int.Parse(buf["mlen"]);

            DilithiumParameters parameters = paramDict[name];

            DilithiumPublicKeyParameters publicKeyParams = new DilithiumPublicKeyParameters(parameters,pk);
            DilithiumSigner verifier = new DilithiumSigner();

            verifier.Init(false,publicKeyParams);
            byte[] detachedSig = Arrays.CopyOfRange(sm,0,smlen-mlen);
            
            bool valid = verifier.VerifySignature(message,detachedSig);
            Assert.True(valid, "FAILED signature verify: " + name + " " + count);
            
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,DilithiumParameters>> testFunc,Dictionary<string,DilithiumParameters> parameters)
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
