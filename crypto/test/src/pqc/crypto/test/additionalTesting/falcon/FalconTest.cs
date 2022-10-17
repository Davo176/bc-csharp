using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Falcon;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class FalconTests
    {
        private static readonly Dictionary<string, FalconParameters> addRandVectors = new Dictionary<string, FalconParameters>()
        {
            { "falcon512-Rand.rsp", FalconParameters.falcon_512 },
            { "falcon1024-Rand.rsp", FalconParameters.falcon_1024 },
        };
        private static readonly List<string> addRandVectorsFileNames = new List<string>(addRandVectors.Keys);

        private static readonly Dictionary<string, FalconParameters> interopKgVectors = new Dictionary<string, FalconParameters>()
        {
             { "keypairs_csharp_falcon512.rsp", FalconParameters.falcon_512 },
             { "keypairs_csharp_falcon1024.rsp", FalconParameters.falcon_1024 },
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, FalconParameters> interopSignedVectors = new Dictionary<string, FalconParameters>()
        {
             { "keypairs_ref_falcon512.rsp", FalconParameters.falcon_512 },
             { "keypairs_ref_falcon1024.rsp", FalconParameters.falcon_1024 },
        };
        private static readonly List<string> interopSignedVectorsFileNames = new List<string>(interopSignedVectors.Keys);

        private static readonly Dictionary<string, FalconParameters> interopCheckSignedVectors = new Dictionary<string, FalconParameters>()
        {
             { "signed_csharp_ref_falcon512.rsp", FalconParameters.falcon_512 },
             { "signed_csharp_ref_falcon1024.rsp", FalconParameters.falcon_1024 },
        };
        private static readonly List<string> interopCheckSignedVectorsFileNames = new List<string>(interopCheckSignedVectors.Keys);

        [TestCaseSource(nameof(addRandVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.falcon.addRand.",FullTests,addRandVectors);
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
            RunTest(interopFile,"pqc.falcon.interoperability.",CreateSigned,interopSignedVectors);
        }

        [TestCaseSource(nameof(interopCheckSignedVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCheckSigned(string interopFile)
        {
            RunTest(interopFile,"pqc.falcon.interoperability.",CheckSigned,interopCheckSignedVectors);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, FalconParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            uint m_len = uint.Parse(buf["mlen"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] expectedSK = Hex.Decode(buf["sk"]);
            byte[] expectedSM = Hex.Decode(buf["sm"]);
            uint expectedSMLEN = uint.Parse(buf["smlen"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            FalconParameters parameters = paramDict[name];

            // Key Generation
            FalconKeyPairGenerator keyGenerator = new FalconKeyPairGenerator();
            FalconKeyGenerationParameters generationParams = new FalconKeyGenerationParameters(random, parameters);
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();
            FalconPublicKeyParameters publicKeyParams = (FalconPublicKeyParameters) keyPair.Public;
            FalconPrivateKeyParameters privateKeyParams = (FalconPrivateKeyParameters) keyPair.Private;

            // Sign
            FalconSigner signer = new FalconSigner();
            ParametersWithRandom skwrand = new ParametersWithRandom(keyPair.Private, random);
            signer.Init(true, skwrand);
            byte[] sig = signer.GenerateSignature(msg);
            byte[] ressm = new byte[2 + msg.Length + sig.Length - 1];
            ressm[0] = (byte)((sig.Length - 40 - 1) >> 8);
            ressm[1] = (byte)(sig.Length - 40 - 1);
            Array.Copy(sig, 1, ressm, 2, 40);
            Array.Copy(msg, 0, ressm, 2 + 40, msg.Length);
            Array.Copy(sig, 40 + 1, ressm, 2 + 40 + msg.Length, sig.Length - 40 - 1);

            // Verify
            FalconSigner verifier = new FalconSigner();
            FalconPublicKeyParameters pkparam = (FalconPublicKeyParameters)keyPair.Public;
            verifier.Init(false, pkparam);
            byte[] noncesig = new byte[expectedSMLEN - m_len - 2 + 1];
            noncesig[0] = (byte)(0x30 + parameters.LogN);
            Array.Copy(expectedSM, 2, noncesig, 1, 40);
            Array.Copy(expectedSM, 2 + 40 + m_len, noncesig, 40 + 1, expectedSMLEN - 2 - 40 - m_len);
            bool vrfyrespass = verifier.VerifySignature(msg, noncesig);
            noncesig[42]++; // changing the signature by 1 byte should cause it to fail
            bool vrfyresfail = verifier.VerifySignature(msg, noncesig);

            // Assert.True
            //keyGenerator
            Assert.True(Arrays.AreEqual(publicKeyParams.GetEncoded(),0,publicKeyParams.GetEncoded().Length, expectedPK,1,expectedPK.Length), name + " " + count + " public key");
            Assert.True(Arrays.AreEqual(privateKeyParams.GetEncoded(),0,privateKeyParams.GetEncoded().Length, expectedSK,1,expectedSK.Length), name + " " + count + " private key");
            //sign
            Assert.True(Arrays.AreEqual(ressm, expectedSM), name + " " + count + " signature");
            //verify
            Assert.True(vrfyrespass, name + " " + count + " verify failed when should pass");
            Assert.False(vrfyresfail, name + " " + count + " verify passed when should fail");
        }

        public static void CreateKeypairs(string name,Dictionary<string, FalconParameters> paramDict){
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
            FalconParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/falcon/interoperability/"+name;

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                int messageLength = 33*(i+1);
                byte[] message = new byte[messageLength];
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                FalconKeyPairGenerator keysGenerator = new FalconKeyPairGenerator();
                FalconKeyGenerationParameters generationParams = new FalconKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();
                random.NextBytes(message,0,messageLength);

                FalconPublicKeyParameters publicKeyParams = (FalconPublicKeyParameters)keys.Public;
                FalconPrivateKeyParameters privateKeyParams = (FalconPrivateKeyParameters)keys.Private;
                //all falcon pks start with 09 or 0A - depending on parameters
                f1Contents += "mlen = " + messageLength.ToString()+"\n";
                f1Contents += "msg = " + Hex.ToHexString(message)+"\n";
                if (parameters.Name=="falcon512"){
                    f1Contents += "pk = 09" + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                    f1Contents += "sk = 59" + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                }else{
                    f1Contents += "pk = 0A" + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                    f1Contents += "sk = 5A" + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                }
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        public static void CreateSigned(string name, IDictionary<string, string> buf,Dictionary<string, FalconParameters> paramDict){
            String count = buf["count"];
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            byte[] shortSK = Arrays.CopyOfRange(sk,1,sk.Length);

            FalconParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/falcon/interoperability/signed_csharp_"+name.Substring("keypairs_ref_".Length,name.Length-"keypairs_ref_".Length);

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            f1Contents += "pk = "+buf["pk"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);

            FalconPrivateKeyParameters privateKeyParams = new FalconPrivateKeyParameters(parameters,shortSK);
            ParametersWithRandom skwrand = new ParametersWithRandom(privateKeyParams, random);
            FalconSigner signer = new FalconSigner();

            signer.Init(true,privateKeyParams);
            
            byte[] sig = signer.GenerateSignature(msg);
            byte[] ressm = new byte[2 + msg.Length + sig.Length - 1];
            ressm[0] = (byte)((sig.Length - 40 - 1) >> 8);
            ressm[1] = (byte)(sig.Length - 40 - 1);
            Array.Copy(sig, 1, ressm, 2, 40);
            Array.Copy(msg, 0, ressm, 2 + 40, msg.Length);
            Array.Copy(sig, 40 + 1, ressm, 2 + 40 + msg.Length, sig.Length - 40 - 1);

            f1Contents += "mlen = " + buf["mlen"] + "\n";
            f1Contents += "msg = " + buf["msg"] + "\n";
            f1Contents += "smlen = " + ressm.Length.ToString() + "\n";
            f1Contents += "sm = " + Hex.ToHexString(ressm) + "\n";
            
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
        }

        public static void CheckSigned(string name, IDictionary<string, string> buf,Dictionary<string, FalconParameters> paramDict){
            String count = buf["count"];
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] message = Hex.Decode(buf["msg"]);
            byte[] sm = Hex.Decode(buf["sm"]);
            int smlen = int.Parse(buf["smlen"]);
            int mlen = int.Parse(buf["mlen"]);

            byte[] shortPK = Arrays.CopyOfRange(pk,1,pk.Length);


            FalconParameters parameters = paramDict[name];

            FalconPublicKeyParameters publicKeyParams = new FalconPublicKeyParameters(parameters,shortPK);
            FalconSigner verifier = new FalconSigner();

            verifier.Init(false,publicKeyParams);
            byte[] noncesig = new byte[smlen - mlen - 2 + 1];
            noncesig[0] = (byte)(0x30 + parameters.LogN);
            Array.Copy(sm, 2, noncesig, 1, 40);
            Array.Copy(sm, 2 + 40 + mlen, noncesig, 40 + 1, smlen - 2 - 40 - mlen);
            bool valid = verifier.VerifySignature(message, noncesig);
            
            Assert.True(valid, "FAILED signature verify: " + name + " " + count);
            
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,FalconParameters>> testFunc,Dictionary<string,FalconParameters> parameters)
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
