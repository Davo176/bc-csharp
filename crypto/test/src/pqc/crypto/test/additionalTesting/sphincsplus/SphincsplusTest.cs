using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Pqc.Crypto.Utilities;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Tests.additionalTests
{
    [TestFixture]
    public class sphincsplusTest
    {
        private static readonly Dictionary<string, SPHINCSPlusParameters> fullTestVectorsRobustFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "subset_sha2-128f-robust.rsp", SPHINCSPlusParameters.sha2_128f },
            { "subset_sha2-192f-robust.rsp", SPHINCSPlusParameters.sha2_192f },
            { "subset_sha2-256f-robust.rsp", SPHINCSPlusParameters.sha2_256f },
            { "subset_shake-128f-robust.rsp", SPHINCSPlusParameters.shake_128f },
            { "subset_shake-192f-robust.rsp", SPHINCSPlusParameters.shake_192f },
            { "subset_shake-256f-robust.rsp", SPHINCSPlusParameters.shake_256f },
            { "subset_haraka-128f-robust.rsp", SPHINCSPlusParameters.haraka_128f },
            { "subset_haraka-192f-robust.rsp", SPHINCSPlusParameters.haraka_192f },
            { "subset_haraka-256f-robust.rsp", SPHINCSPlusParameters.haraka_256f },
        };
        private static readonly List<string> fullTestVectorFileNamesRobustFast = new List<string>(fullTestVectorsRobustFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> fullTestVectorsRobustSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "subset_sha2-128s-robust.rsp", SPHINCSPlusParameters.sha2_128s },
            { "subset_sha2-192s-robust.rsp", SPHINCSPlusParameters.sha2_192s },
            { "subset_sha2-256s-robust.rsp", SPHINCSPlusParameters.sha2_256s },
            { "subset_shake-128s-robust.rsp", SPHINCSPlusParameters.shake_128s },
            { "subset_shake-192s-robust.rsp", SPHINCSPlusParameters.shake_192s },
            { "subset_shake-256s-robust.rsp", SPHINCSPlusParameters.shake_256s },
            { "subset_haraka-128s-robust.rsp", SPHINCSPlusParameters.haraka_128s },
            { "subset_haraka-192s-robust.rsp", SPHINCSPlusParameters.haraka_192s },
            { "subset_haraka-256s-robust.rsp", SPHINCSPlusParameters.haraka_256s },
        };
        private static readonly List<string> fullTestVectorFileNamesRobustSlow = new List<string>(fullTestVectorsRobustSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> fullTestVectorsSimpleFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "subset_sha2-128f-simple.rsp", SPHINCSPlusParameters.sha2_128f_simple },
            { "subset_sha2-192f-simple.rsp", SPHINCSPlusParameters.sha2_192f_simple },
            { "subset_sha2-256f-simple.rsp", SPHINCSPlusParameters.sha2_256f_simple },
            { "subset_shake-128f-simple.rsp", SPHINCSPlusParameters.shake_128f_simple },
            { "subset_shake-192f-simple.rsp", SPHINCSPlusParameters.shake_192f_simple },
            { "subset_shake-256f-simple.rsp", SPHINCSPlusParameters.shake_256f_simple },
            { "subset_haraka-128f-simple.rsp", SPHINCSPlusParameters.haraka_128f_simple },
            { "subset_haraka-192f-simple.rsp", SPHINCSPlusParameters.haraka_192f_simple },
            { "subset_haraka-256f-simple.rsp", SPHINCSPlusParameters.haraka_256f_simple },
        };
        private static readonly List<string> fullTestVectorFileNamesSimpleFast = new List<string>(fullTestVectorsSimpleFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> fullTestVectorsSimpleSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "subset_sha2-128s-simple.rsp", SPHINCSPlusParameters.sha2_128s_simple },
            { "subset_sha2-192s-simple.rsp", SPHINCSPlusParameters.sha2_192s_simple },
            { "subset_sha2-256s-simple.rsp", SPHINCSPlusParameters.sha2_256s_simple },
            { "subset_shake-128s-simple.rsp", SPHINCSPlusParameters.shake_128s_simple },
            { "subset_shake-192s-simple.rsp", SPHINCSPlusParameters.shake_192s_simple },
            { "subset_shake-256s-simple.rsp", SPHINCSPlusParameters.shake_256s_simple },
            { "subset_haraka-128s-simple.rsp", SPHINCSPlusParameters.haraka_128s_simple },
            { "subset_haraka-192s-simple.rsp", SPHINCSPlusParameters.haraka_192s_simple },
            { "subset_haraka-256s-simple.rsp", SPHINCSPlusParameters.haraka_256s_simple },
        };
        private static readonly List<string> fullTestVectorFileNamesSimpleSlow = new List<string>(fullTestVectorsSimpleSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addRandTestVectorsRobustFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128f-robust.rsp", SPHINCSPlusParameters.sha2_128f },
            { "sphincs-sha2-192f-robust.rsp", SPHINCSPlusParameters.sha2_192f },
            { "sphincs-sha2-256f-robust.rsp", SPHINCSPlusParameters.sha2_256f },
            { "sphincs-shake-128f-robust.rsp", SPHINCSPlusParameters.shake_128f },
            { "sphincs-shake-192f-robust.rsp", SPHINCSPlusParameters.shake_192f },
            { "sphincs-shake-256f-robust.rsp", SPHINCSPlusParameters.shake_256f },
            { "sphincs-haraka-128f-robust.rsp", SPHINCSPlusParameters.haraka_128f },
            { "sphincs-haraka-192f-robust.rsp", SPHINCSPlusParameters.haraka_192f },
            { "sphincs-haraka-256f-robust.rsp", SPHINCSPlusParameters.haraka_256f },
        };
        private static readonly List<string> addRandTestVectorFileNamesRobustFast = new List<string>(addRandTestVectorsRobustFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addRandTestVectorsRobustSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128s-robust.rsp", SPHINCSPlusParameters.sha2_128s },
            { "sphincs-sha2-192s-robust.rsp", SPHINCSPlusParameters.sha2_192s },
            { "sphincs-sha2-256s-robust.rsp", SPHINCSPlusParameters.sha2_256s },
            { "sphincs-shake-128s-robust.rsp", SPHINCSPlusParameters.shake_128s },
            { "sphincs-shake-192s-robust.rsp", SPHINCSPlusParameters.shake_192s },
            { "sphincs-shake-256s-robust.rsp", SPHINCSPlusParameters.shake_256s },
            { "sphincs-haraka-128s-robust.rsp", SPHINCSPlusParameters.haraka_128s },
            { "sphincs-haraka-192s-robust.rsp", SPHINCSPlusParameters.haraka_192s },
            { "sphincs-haraka-256s-robust.rsp", SPHINCSPlusParameters.haraka_256s },
        };
        private static readonly List<string> addRandTestVectorFileNamesRobustSlow = new List<string>(addRandTestVectorsRobustSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addRandTestVectorsSimpleFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128f-simple.rsp", SPHINCSPlusParameters.sha2_128f_simple },
            { "sphincs-sha2-192f-simple.rsp", SPHINCSPlusParameters.sha2_192f_simple },
            { "sphincs-sha2-256f-simple.rsp", SPHINCSPlusParameters.sha2_256f_simple },
            { "sphincs-shake-128f-simple.rsp", SPHINCSPlusParameters.shake_128f_simple },
            { "sphincs-shake-192f-simple.rsp", SPHINCSPlusParameters.shake_192f_simple },
            { "sphincs-shake-256f-simple.rsp", SPHINCSPlusParameters.shake_256f_simple },
            { "sphincs-haraka-128f-simple.rsp", SPHINCSPlusParameters.haraka_128f_simple },
            { "sphincs-haraka-192f-simple.rsp", SPHINCSPlusParameters.haraka_192f_simple },
            { "sphincs-haraka-256f-simple.rsp", SPHINCSPlusParameters.haraka_256f_simple },
        };
        private static readonly List<string> addRandTestVectorFileNamesSimpleFast = new List<string>(addRandTestVectorsSimpleFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addRandTestVectorsSimpleSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128s-simple.rsp", SPHINCSPlusParameters.sha2_128s_simple },
            { "sphincs-sha2-192s-simple.rsp", SPHINCSPlusParameters.sha2_192s_simple },
            { "sphincs-sha2-256s-simple.rsp", SPHINCSPlusParameters.sha2_256s_simple },
            { "sphincs-shake-128s-simple.rsp", SPHINCSPlusParameters.shake_128s_simple },
            { "sphincs-shake-192s-simple.rsp", SPHINCSPlusParameters.shake_192s_simple },
            { "sphincs-shake-256s-simple.rsp", SPHINCSPlusParameters.shake_256s_simple },
            { "sphincs-haraka-128s-simple.rsp", SPHINCSPlusParameters.haraka_128s_simple },
            { "sphincs-haraka-192s-simple.rsp", SPHINCSPlusParameters.haraka_192s_simple },
            { "sphincs-haraka-256s-simple.rsp", SPHINCSPlusParameters.haraka_256s_simple },
        };
        private static readonly List<string> addRandTestVectorFileNamesSimpleSlow = new List<string>(addRandTestVectorsSimpleSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addSignTestVectorsRobustFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128f-robust-sign.rsp", SPHINCSPlusParameters.sha2_128f },
            { "sphincs-sha2-192f-robust-sign.rsp", SPHINCSPlusParameters.sha2_192f },
            { "sphincs-sha2-256f-robust-sign.rsp", SPHINCSPlusParameters.sha2_256f },
            { "sphincs-shake-128f-robust-sign.rsp", SPHINCSPlusParameters.shake_128f },
            { "sphincs-shake-192f-robust-sign.rsp", SPHINCSPlusParameters.shake_192f },
            { "sphincs-shake-256f-robust-sign.rsp", SPHINCSPlusParameters.shake_256f },
            { "sphincs-haraka-128f-robust-sign.rsp", SPHINCSPlusParameters.haraka_128f },
            { "sphincs-haraka-192f-robust-sign.rsp", SPHINCSPlusParameters.haraka_192f },
            { "sphincs-haraka-256f-robust-sign.rsp", SPHINCSPlusParameters.haraka_256f },
        };
        private static readonly List<string> addSignTestVectorFileNamesRobustFast = new List<string>(addSignTestVectorsRobustFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addSignTestVectorsRobustSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128s-robust-sign.rsp", SPHINCSPlusParameters.sha2_128s },
            { "sphincs-sha2-192s-robust-sign.rsp", SPHINCSPlusParameters.sha2_192s },
            { "sphincs-sha2-256s-robust-sign.rsp", SPHINCSPlusParameters.sha2_256s },
            { "sphincs-shake-128s-robust-sign.rsp", SPHINCSPlusParameters.shake_128s },
            { "sphincs-shake-192s-robust-sign.rsp", SPHINCSPlusParameters.shake_192s },
            { "sphincs-shake-256s-robust-sign.rsp", SPHINCSPlusParameters.shake_256s },
            { "sphincs-haraka-128s-robust-sign.rsp", SPHINCSPlusParameters.haraka_128s },
            { "sphincs-haraka-192s-robust-sign.rsp", SPHINCSPlusParameters.haraka_192s },
            { "sphincs-haraka-256s-robust-sign.rsp", SPHINCSPlusParameters.haraka_256s },
        };
        private static readonly List<string> addSignTestVectorFileNamesRobustSlow = new List<string>(addSignTestVectorsRobustSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addSignTestVectorsSimpleFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128f-simple-sign.rsp", SPHINCSPlusParameters.sha2_128f_simple },
            { "sphincs-sha2-192f-simple-sign.rsp", SPHINCSPlusParameters.sha2_192f_simple },
            { "sphincs-sha2-256f-simple-sign.rsp", SPHINCSPlusParameters.sha2_256f_simple },
            { "sphincs-shake-128f-simple-sign.rsp", SPHINCSPlusParameters.shake_128f_simple },
            { "sphincs-shake-192f-simple-sign.rsp", SPHINCSPlusParameters.shake_192f_simple },
            { "sphincs-shake-256f-simple-sign.rsp", SPHINCSPlusParameters.shake_256f_simple },
            { "sphincs-haraka-128f-simple-sign.rsp", SPHINCSPlusParameters.haraka_128f_simple },
            { "sphincs-haraka-192f-simple-sign.rsp", SPHINCSPlusParameters.haraka_192f_simple },
            { "sphincs-haraka-256f-simple-sign.rsp", SPHINCSPlusParameters.haraka_256f_simple },
        };
        private static readonly List<string> addSignTestVectorFileNamesSimpleFast = new List<string>(addSignTestVectorsSimpleFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> addSignTestVectorsSimpleSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "sphincs-sha2-128s-simple-sign.rsp", SPHINCSPlusParameters.sha2_128s_simple },
            { "sphincs-sha2-192s-simple-sign.rsp", SPHINCSPlusParameters.sha2_192s_simple },
            { "sphincs-sha2-256s-simple-sign.rsp", SPHINCSPlusParameters.sha2_256s_simple },
            { "sphincs-shake-128s-simple-sign.rsp", SPHINCSPlusParameters.shake_128s_simple },
            { "sphincs-shake-192s-simple-sign.rsp", SPHINCSPlusParameters.shake_192s_simple },
            { "sphincs-shake-256s-simple-sign.rsp", SPHINCSPlusParameters.shake_256s_simple },
            { "sphincs-haraka-128s-simple-sign.rsp", SPHINCSPlusParameters.haraka_128s_simple },
            { "sphincs-haraka-192s-simple-sign.rsp", SPHINCSPlusParameters.haraka_192s_simple },
            { "sphincs-haraka-256s-simple-sign.rsp", SPHINCSPlusParameters.haraka_256s_simple },
        };
        private static readonly List<string> addSignTestVectorFileNamesSimpleSlow = new List<string>(addSignTestVectorsSimpleSlow.Keys);

        [TestCaseSource(nameof(fullTestVectorFileNamesRobustFast))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullRobustFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.",FullTests,fullTestVectorsRobustFast);
        }

        [TestCaseSource(nameof(fullTestVectorFileNamesRobustSlow))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullRobustSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.",FullTests,fullTestVectorsRobustSlow);
        }

        [TestCaseSource(nameof(fullTestVectorFileNamesSimpleFast))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullSimpleFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.",FullTests,fullTestVectorsSimpleFast);
        }

        [TestCaseSource(nameof(fullTestVectorFileNamesSimpleSlow))]
        [Parallelizable(ParallelScope.All)]
        public void TestFullSimpleSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.",FullTests,fullTestVectorsSimpleSlow);
        }

        [TestCaseSource(nameof(addRandTestVectorFileNamesRobustFast))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddRandRobustFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addRand.",FullTests,addRandTestVectorsRobustFast);
        }

        [TestCaseSource(nameof(addRandTestVectorFileNamesRobustSlow))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddRandRobustSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addRand.",FullTests,addRandTestVectorsRobustSlow);
        }

        [TestCaseSource(nameof(addRandTestVectorFileNamesSimpleFast))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddRandSimpleFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addRand.",FullTests,addRandTestVectorsSimpleFast);
        }

        [TestCaseSource(nameof(addRandTestVectorFileNamesSimpleSlow))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddRandSimpleSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addRand.",FullTests,addRandTestVectorsSimpleSlow);
        }

        [TestCaseSource(nameof(addSignTestVectorFileNamesRobustFast))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddSignRobustFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addSign.",SignTests,addSignTestVectorsRobustFast);
        }

        [TestCaseSource(nameof(addSignTestVectorFileNamesRobustSlow))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddSignRobustSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addSign.",SignTests,addSignTestVectorsRobustSlow);
        }

        [TestCaseSource(nameof(addSignTestVectorFileNamesSimpleFast))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddSignSimpleFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addSign.",SignTests,addSignTestVectorsSimpleFast);
        }

        [TestCaseSource(nameof(addSignTestVectorFileNamesSimpleSlow))]
        [Parallelizable(ParallelScope.All)]
        public void TestAddSignSimpleSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.addSign.",SignTests,addSignTestVectorsSimpleSlow);
        }

        private static void FullTests(string name, IDictionary<string, string> buf,Dictionary<string, SPHINCSPlusParameters> paramDict)
        {
            string count = buf["count"];
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            byte[] sigExpected = Hex.Decode(buf["sm"]);
            byte[] oprR = Hex.Decode(buf["optrand"]);

            Console.Error.WriteLine(name);
            Console.Error.WriteLine(count);

            SPHINCSPlusKeyPairGenerator kpGen = new SPHINCSPlusKeyPairGenerator();

            FixedSecureRandom.Source[] source = { new FixedSecureRandom.Source(sk) };
            SecureRandom random = new FixedSecureRandom(source);

            SPHINCSPlusParameters parameters = paramDict[name];

            //
            // Generate keys and test.
            //
            kpGen.Init(new SPHINCSPlusKeyGenerationParameters(random, parameters));
            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            SPHINCSPlusPublicKeyParameters publicKeyParams = (SPHINCSPlusPublicKeyParameters)kp.Public;
            SPHINCSPlusPrivateKeyParameters privateKeyParams = (SPHINCSPlusPrivateKeyParameters)kp.Private;

            Assert.True(Arrays.AreEqual(Arrays.Concatenate(publicKeyParams.GetParameters().GetEncoded(), expectedPK), publicKeyParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(Arrays.Concatenate(privateKeyParams.GetParameters().GetEncoded(), sk), privateKeyParams.GetEncoded()), name + " " + count + ": secret key");

            //
            // Signature test
            //

            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

            FixedSecureRandom.Source[] s1 = { new FixedSecureRandom.Source(oprR) };
            signer.Init(true, new ParametersWithRandom(privateKeyParams, new FixedSecureRandom(s1)));

            byte[] sigGenerated = signer.GenerateSignature(msg);
            byte[] attachedSig = Arrays.Concatenate(sigGenerated, msg);


            signer.Init(false, publicKeyParams);

            Assert.True(signer.VerifySignature(msg, sigGenerated), name + " " + count + ": signature verify");
            Assert.True(Arrays.AreEqual(sigExpected, attachedSig), name + " " + count + ": signature gen match");
        }

        private static void SignTests(string name, IDictionary<string, string> buf,Dictionary<string, SPHINCSPlusParameters> paramDict)
        {
            string count = buf["count"];
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            byte[] sigExpected = Hex.Decode(buf["sm"]);
            byte[] oprR = Hex.Decode(buf["optrand"]);

            SPHINCSPlusKeyPairGenerator kpGen = new SPHINCSPlusKeyPairGenerator();

            SPHINCSPlusParameters parameters = paramDict[name];

            SPHINCSPlusPrivateKeyParameters privateKeyParams = new SPHINCSPlusPrivateKeyParameters(parameters,sk);

            Console.Error.WriteLine(name);
            Console.Error.WriteLine(count);

            //
            // Signature test
            //

            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

            FixedSecureRandom.Source[] s1 = { new FixedSecureRandom.Source(oprR) };
            signer.Init(true, new ParametersWithRandom(privateKeyParams, new FixedSecureRandom(s1)));

            byte[] sigGenerated = signer.GenerateSignature(msg);
            byte[] attachedSig = Arrays.Concatenate(sigGenerated, msg);

            Assert.True(Arrays.AreEqual(sigExpected, attachedSig), name + " " + count + ": signature gen match");
        }

        //How I would expect it to work - doesnt work with SHA or SHAKE but works with Haraka
        private static void FullTestsNISTRandom(string name, IDictionary<string, string> buf,Dictionary<string, SPHINCSPlusParameters> paramDict)
        {
            string count = buf["count"];
            byte[] seed = Hex.Decode(buf["seed"]);
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] expectedPK = Hex.Decode(buf["pk"]);
            byte[] msg = Hex.Decode(buf["msg"]);
            byte[] sigExpected = Hex.Decode(buf["sm"]);

            NistSecureRandom random = new NistSecureRandom(seed, null);
            SPHINCSPlusParameters parameters = paramDict[name];

            SPHINCSPlusKeyPairGenerator keyGenerator = new SPHINCSPlusKeyPairGenerator();
            SPHINCSPlusKeyGenerationParameters generationParams = new SPHINCSPlusKeyGenerationParameters(random,parameters);

            //
            // Generate keys and test.
            //
            keyGenerator.Init(generationParams);
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            SPHINCSPlusPublicKeyParameters publicKeyParams = (SPHINCSPlusPublicKeyParameters)keyPair.Public;
            SPHINCSPlusPrivateKeyParameters privateKeyParams = (SPHINCSPlusPrivateKeyParameters)keyPair.Private;

            //
            // Signature test
            //

            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

            signer.Init(true, new ParametersWithRandom(privateKeyParams,random));


            byte[] sigGenerated = signer.GenerateSignature(msg);
            byte[] attachedSig = Arrays.Concatenate(sigGenerated, msg);

            signer.Init(false, publicKeyParams);

            Assert.True(Arrays.AreEqual(Arrays.Concatenate(publicKeyParams.GetParameters().GetEncoded(), expectedPK), publicKeyParams.GetEncoded()), name + " " + count + ": public key");
            Assert.True(Arrays.AreEqual(Arrays.Concatenate(privateKeyParams.GetParameters().GetEncoded(), sk), privateKeyParams.GetEncoded()), name + " " + count + ": secret key");

            Assert.True(Arrays.AreEqual(sigExpected, attachedSig), name + " " + count + ": signature gen match");
            Assert.True(signer.VerifySignature(msg, sigGenerated), name + " " + count + ": signature verify");
        }

        public static void RunTest(string name,string partialLocation, Action<string,Dictionary<string,string>,Dictionary<string,SPHINCSPlusParameters>> testFunc,Dictionary<string,SPHINCSPlusParameters> parameters)
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
