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
