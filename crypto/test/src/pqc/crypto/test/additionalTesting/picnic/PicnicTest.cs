using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Picnic;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class PicnicTest
    {
        private static readonly Dictionary<string, PicnicParameters> fullTestVectors = new Dictionary<string, PicnicParameters>()
        {
             { "picnicl1fs.rsp", PicnicParameters.picnicl1fs },
            { "picnicl1ur.rsp", PicnicParameters.picnicl1ur },
            { "picnicl3fs.rsp", PicnicParameters.picnicl3fs },
            { "picnicl3ur.rsp", PicnicParameters.picnicl3ur },
            { "picnicl5fs.rsp", PicnicParameters.picnicl5fs },
            { "picnicl5ur.rsp", PicnicParameters.picnicl5ur },
            { "picnic3l1.rsp", PicnicParameters.picnic3l1 },
            { "picnic3l3.rsp", PicnicParameters.picnic3l3 },
            { "picnic3l5.rsp", PicnicParameters.picnic3l5 },
            { "picnicl1full.rsp", PicnicParameters.picnicl1full },
            { "picnicl3full.rsp", PicnicParameters.picnicl3full },
            { "picnicl5full.rsp", PicnicParameters.picnicl5full },
        };
        private static readonly List<string> fullTestVectorFileNames = new List<string>(fullTestVectors.Keys);

        private static readonly Dictionary<string, PicnicParameters> addRandTestVectors = new Dictionary<string, PicnicParameters>()
        {
             { "addRand_l1fs.rsp", PicnicParameters.picnicl1fs },
            { "addRand_l1ur.rsp", PicnicParameters.picnicl1ur },
            { "addRand_l3fs.rsp", PicnicParameters.picnicl3fs },
            { "addRand_l3ur.rsp", PicnicParameters.picnicl3ur },
            { "addRand_l5fs.rsp", PicnicParameters.picnicl5fs },
            { "addRand_l5ur.rsp", PicnicParameters.picnicl5ur },
            { "addRand_3l1.rsp", PicnicParameters.picnic3l1 },
            { "addRand_3l3.rsp", PicnicParameters.picnic3l3 },
            { "addRand_3l5.rsp", PicnicParameters.picnic3l5 },
            { "addRand_l1full.rsp", PicnicParameters.picnicl1full },
            { "addRand_l3full.rsp", PicnicParameters.picnicl3full },
            { "addRand_l5full.rsp", PicnicParameters.picnicl5full },
        };
        private static readonly List<string> addRandTestVectorFileNames = new List<string>(addRandTestVectors.Keys);

        private static readonly Dictionary<string, PicnicParameters> interopKgVectors = new Dictionary<string, PicnicParameters>()
        {
             { "three/keypairs_csharp_L1.rsp", PicnicParameters.picnic3l1 },
             { "three/keypairs_csharp_L3.rsp", PicnicParameters.picnic3l3 },
             { "three/keypairs_csharp_L5.rsp", PicnicParameters.picnic3l5 },
             { "fs/keypairs_csharp_L1.rsp", PicnicParameters.picnicl1fs },
             { "fs/keypairs_csharp_L3.rsp", PicnicParameters.picnicl3fs },
             { "fs/keypairs_csharp_L5.rsp", PicnicParameters.picnicl5fs },
             { "full/keypairs_csharp_L1.rsp", PicnicParameters.picnicl1full },
             { "full/keypairs_csharp_L3.rsp", PicnicParameters.picnicl3full },
             { "full/keypairs_csharp_L5.rsp", PicnicParameters.picnicl5full },
             { "ur/keypairs_csharp_L1.rsp", PicnicParameters.picnicl1ur },
             { "ur/keypairs_csharp_L3.rsp", PicnicParameters.picnicl3ur },
             { "ur/keypairs_csharp_L5.rsp", PicnicParameters.picnicl5ur },
        };
        private static readonly List<string> interopKgVectorsFileNames = new List<string>(interopKgVectors.Keys);

        private static readonly Dictionary<string, PicnicParameters> interopSignedVectors = new Dictionary<string, PicnicParameters>()
        {
             { "three.keypairs_ref_L1.rsp", PicnicParameters.picnic3l1 },
             { "three.keypairs_ref_L3.rsp", PicnicParameters.picnic3l3 },
             { "three.keypairs_ref_L5.rsp", PicnicParameters.picnic3l5 },
             { "fs.keypairs_ref_L1.rsp", PicnicParameters.picnicl1fs },
             { "fs.keypairs_ref_L3.rsp", PicnicParameters.picnicl3fs },
             { "fs.keypairs_ref_L5.rsp", PicnicParameters.picnicl5fs },
             { "full.keypairs_ref_L1.rsp", PicnicParameters.picnicl1full },
             { "full.keypairs_ref_L3.rsp", PicnicParameters.picnicl3full },
             { "full.keypairs_ref_L5.rsp", PicnicParameters.picnicl5full },
             { "ur.keypairs_ref_L1.rsp", PicnicParameters.picnicl1ur },
             { "ur.keypairs_ref_L3.rsp", PicnicParameters.picnicl3ur },
             { "ur.keypairs_ref_L5.rsp", PicnicParameters.picnicl5ur },
        };
        private static readonly List<string> interopSignedVectorsFileNames = new List<string>(interopSignedVectors.Keys);

        private static readonly Dictionary<string, PicnicParameters> interopcheckSignedVectors = new Dictionary<string, PicnicParameters>()
        {
            //  { "three.signed_csharp_ref_L1.rsp", PicnicParameters.picnic3l1 },
            //  { "three.signed_csharp_ref_L3.rsp", PicnicParameters.picnic3l3 },
            //  { "three.signed_csharp_ref_L5.rsp", PicnicParameters.picnic3l5 },
            //  { "fs.signed_csharp_ref_L1.rsp", PicnicParameters.picnicl1fs },
            //  { "fs.signed_csharp_ref_L3.rsp", PicnicParameters.picnicl3fs },
            //  { "fs.signed_csharp_ref_L5.rsp", PicnicParameters.picnicl5fs },
            //  { "full.signed_csharp_ref_L1.rsp", PicnicParameters.picnicl1full },
            //  { "full.signed_csharp_ref_L3.rsp", PicnicParameters.picnicl3full },
            //  { "full.signed_csharp_ref_L5.rsp", PicnicParameters.picnicl5full },
             { "ur.signed_csharp_ref_L1.rsp", PicnicParameters.picnicl1ur },
             { "ur.signed_csharp_ref_L3.rsp", PicnicParameters.picnicl3ur },
             { "ur.signed_csharp_ref_L5.rsp", PicnicParameters.picnicl5ur },
        };
        private static readonly List<string> interopcheckSignedVectorsFileNames = new List<string>(interopcheckSignedVectors.Keys);


        [TestCaseSource(nameof(fullTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.picnic.",FullTests,fullTestVectors);
        }

        [TestCaseSource(nameof(addRandTestVectorFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddRandVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.picnic.addRandTest.",FullTests,addRandTestVectors);
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
            RunTest(interopFile,"pqc.picnic.interoperability.",CreateSigned,interopSignedVectors);
        }

        [TestCaseSource(nameof(interopcheckSignedVectorsFileNames))]
        [Parallelizable(ParallelScope.All)]
        public void runCheckSigned(string interopFile)
        {
            RunTest(interopFile,"pqc.picnic.interoperability.",CheckSigned,interopcheckSignedVectors);
        }

        public static void CheckSigned(string name, IDictionary<string, string> buf,Dictionary<string, PicnicParameters> paramDict){
            String count = buf["count"];
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] message = Hex.Decode(buf["msg"]);
            byte[] sm = Hex.Decode(buf["sm"]);
            int smlen = int.Parse(buf["smlen"]);
            int mlen = int.Parse(buf["mlen"]);

            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            PicnicParameters parameters = paramDict[name];

            NistSecureRandom random = new NistSecureRandom(entropy_input,null);

            PicnicPublicKeyParameters publicKeyParams = new PicnicPublicKeyParameters(parameters,pk);
            PicnicSigner verifier = new PicnicSigner(random);

            verifier.Init(false,publicKeyParams);
            
            bool valid = verifier.VerifySignature(message,sm);
            Assert.True(valid, "FAILED signature verify: " + name + " " + count);
            
        }

        public static void CreateSigned(string name, IDictionary<string, string> buf,Dictionary<string, PicnicParameters> paramDict){
            String count = buf["count"];
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] message = Hex.Decode(buf["msg"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            PicnicParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/picnic/interoperability/"+name.Substring(0,name.Length-"keypairs_ref_XX.rsp".Length-1)+"/signed_csharp_"+name.Substring(name.Length-6,2)+".rsp";
            Console.WriteLine(f1);
            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            f1Contents += "pk = "+buf["pk"]+"\n";
            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);

            PicnicPrivateKeyParameters privateKeyParams = new PicnicPrivateKeyParameters(parameters,sk);
            PicnicSigner signer = new PicnicSigner(random);

            signer.Init(true,privateKeyParams);
            
            byte[] sigGenerated = signer.GenerateSignature(message);
            byte[] attachedSig = Arrays.ConcatenateAll(UInt32_To_LE((uint)sigGenerated.Length),message,sigGenerated);
            f1Contents += "mlen = " + buf["mlen"] + "\n";
            f1Contents += "msg = " + buf["msg"] + "\n";
            f1Contents += "smlen = " + attachedSig.Length.ToString() + "\n";
            f1Contents += "sm = " + Hex.ToHexString(attachedSig) + "\n";
            
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
        }

        public static void CreateKeypairs(string name,Dictionary<string, PicnicParameters> paramDict){
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
            PicnicParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/picnic/interoperability/"+name;

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                int messageLength = 33*(i+1);
                byte[] message = new byte[messageLength];
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                PicnicKeyPairGenerator keysGenerator = new PicnicKeyPairGenerator();
                PicnicKeyGenerationParameters generationParams = new PicnicKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();
                random.NextBytes(message,0,messageLength);

                PicnicPublicKeyParameters publicKeyParams = (PicnicPublicKeyParameters)keys.Public;
                PicnicPrivateKeyParameters privateKeyParams = (PicnicPrivateKeyParameters)keys.Private;
                f1Contents += "mlen = " + messageLength.ToString()+"\n";
                f1Contents += "msg = " + Hex.ToHexString(message)+"\n";
                f1Contents += "pk = " + Hex.ToHexString(publicKeyParams.GetEncoded())+"\n";
                f1Contents += "sk = " + Hex.ToHexString(privateKeyParams.GetEncoded())+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, PicnicParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);      // seed for picnic secure random
            int mlen = int.Parse(buf["mlen"]);          // message length
            byte[] msg = Hex.Decode(buf["msg"]);        // message
            byte[] expectedPK = Hex.Decode(buf["pk"]);          // public key
            byte[] expectedSK = Hex.Decode(buf["sk"]);          // private key
            int smlen = int.Parse(buf["smlen"]);        // signature length
            byte[] sigExpected = Hex.Decode(buf["sm"]); // signature

            NistSecureRandom random = new NistSecureRandom(seed, null);
            PicnicParameters picnicParameters = paramDict[name];

            PicnicKeyPairGenerator keyGenerator = new PicnicKeyPairGenerator();
            PicnicKeyGenerationParameters generationParams = new PicnicKeyGenerationParameters(random, picnicParameters);

            //
            // Generate keys and test.
            //
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();


            PicnicPublicKeyParameters publicKeyParams = (PicnicPublicKeyParameters)PublicKeyFactory.CreateKey(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public));
            PicnicPrivateKeyParameters privateKeyParams = (PicnicPrivateKeyParameters)PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private));

            Assert.True(Arrays.AreEqual(expectedPK, publicKeyParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(expectedSK, privateKeyParams.GetEncoded()), name + " " + count + ": secret key");

            //
            // Signature test
            //
            PicnicSigner signer = new PicnicSigner(random);

            signer.Init(true, privateKeyParams);
            byte[] sigGenerated = signer.GenerateSignature(msg);
            byte[] attachedSig = Arrays.ConcatenateAll(UInt32_To_LE((uint)sigGenerated.Length), msg, sigGenerated);
            
            Assert.True(smlen == attachedSig.Length, name + " " + count + ": signature length");

            signer.Init(false, publicKeyParams);
            Assert.True(signer.VerifySignature(msg, attachedSig), (name + " " + count + ": signature verify"));
            Assert.True(Arrays.AreEqual(sigExpected, attachedSig), name + " " + count + ": signature gen match");
        }

        private static byte[] UInt32_To_LE(uint n)
        {
            byte[] bs = new byte[4];
            bs[0] = (byte)(n);
            bs[1] = (byte)(n >> 8);
            bs[2] = (byte)(n >> 16);
            bs[3] = (byte)(n >> 24);
            return bs;
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,PicnicParameters>> testFunc,Dictionary<string,PicnicParameters> parameters)
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
