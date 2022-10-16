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
    public class SphincsPlusInteroperability {
        private static readonly Dictionary<string, SPHINCSPlusParameters> createKeyPairsRobustFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_csharp_sha2-128f-robust.rsp", SPHINCSPlusParameters.sha2_128f },
            { "keypairs_csharp_sha2-192f-robust.rsp", SPHINCSPlusParameters.sha2_192f },
            { "keypairs_csharp_sha2-256f-robust.rsp", SPHINCSPlusParameters.sha2_256f },
            { "keypairs_csharp_shake-128f-robust.rsp", SPHINCSPlusParameters.shake_128f },
            { "keypairs_csharp_shake-192f-robust.rsp", SPHINCSPlusParameters.shake_192f },
            { "keypairs_csharp_shake-256f-robust.rsp", SPHINCSPlusParameters.shake_256f },
            { "keypairs_csharp_haraka-128f-robust.rsp", SPHINCSPlusParameters.haraka_128f },
            { "keypairs_csharp_haraka-192f-robust.rsp", SPHINCSPlusParameters.haraka_192f },
            { "keypairs_csharp_haraka-256f-robust.rsp", SPHINCSPlusParameters.haraka_256f },
        };
        private static readonly List<string> CreateKeyPairsVectorFileNamesRobustFast = new List<string>(createKeyPairsRobustFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> createKeyPairsRobustSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_csharp_sha2-128s-robust.rsp", SPHINCSPlusParameters.sha2_128s },
            { "keypairs_csharp_sha2-192s-robust.rsp", SPHINCSPlusParameters.sha2_192s },
            { "keypairs_csharp_sha2-256s-robust.rsp", SPHINCSPlusParameters.sha2_256s },
            { "keypairs_csharp_shake-128s-robust.rsp", SPHINCSPlusParameters.shake_128s },
            { "keypairs_csharp_shake-192s-robust.rsp", SPHINCSPlusParameters.shake_192s },
            { "keypairs_csharp_shake-256s-robust.rsp", SPHINCSPlusParameters.shake_256s },
            { "keypairs_csharp_haraka-128s-robust.rsp", SPHINCSPlusParameters.haraka_128s },
            { "keypairs_csharp_haraka-192s-robust.rsp", SPHINCSPlusParameters.haraka_192s },
            { "keypairs_csharp_haraka-256s-robust.rsp", SPHINCSPlusParameters.haraka_256s },
        };
        private static readonly List<string> CreateKeyPairsVectorFileNamesRobustSlow = new List<string>(createKeyPairsRobustSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> createKeyPairsSimpleFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_csharp_sha2-128f-simple.rsp", SPHINCSPlusParameters.sha2_128f_simple },
            { "keypairs_csharp_sha2-192f-simple.rsp", SPHINCSPlusParameters.sha2_192f_simple },
            { "keypairs_csharp_sha2-256f-simple.rsp", SPHINCSPlusParameters.sha2_256f_simple },
            { "keypairs_csharp_shake-128f-simple.rsp", SPHINCSPlusParameters.shake_128f_simple },
            { "keypairs_csharp_shake-192f-simple.rsp", SPHINCSPlusParameters.shake_192f_simple },
            { "keypairs_csharp_shake-256f-simple.rsp", SPHINCSPlusParameters.shake_256f_simple },
            { "keypairs_csharp_haraka-128f-simple.rsp", SPHINCSPlusParameters.haraka_128f_simple },
            { "keypairs_csharp_haraka-192f-simple.rsp", SPHINCSPlusParameters.haraka_192f_simple },
            { "keypairs_csharp_haraka-256f-simple.rsp", SPHINCSPlusParameters.haraka_256f_simple },
        };
        private static readonly List<string> CreateKeyPairsVectorFileNamesSimpleFast = new List<string>(createKeyPairsSimpleFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> createKeyPairsSimpleSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_csharp_sha2-128s-simple.rsp", SPHINCSPlusParameters.sha2_128s_simple },
            { "keypairs_csharp_sha2-192s-simple.rsp", SPHINCSPlusParameters.sha2_192s_simple },
            { "keypairs_csharp_sha2-256s-simple.rsp", SPHINCSPlusParameters.sha2_256s_simple },
            { "keypairs_csharp_shake-128s-simple.rsp", SPHINCSPlusParameters.shake_128s_simple },
            { "keypairs_csharp_shake-192s-simple.rsp", SPHINCSPlusParameters.shake_192s_simple },
            { "keypairs_csharp_shake-256s-simple.rsp", SPHINCSPlusParameters.shake_256s_simple },
            { "keypairs_csharp_haraka-128s-simple.rsp", SPHINCSPlusParameters.haraka_128s_simple },
            { "keypairs_csharp_haraka-192s-simple.rsp", SPHINCSPlusParameters.haraka_192s_simple },
            { "keypairs_csharp_haraka-256s-simple.rsp", SPHINCSPlusParameters.haraka_256s_simple },
        };
        private static readonly List<string> CreateKeyPairsVectorFileNamesSimpleSlow = new List<string>(createKeyPairsSimpleSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CreateSignedRobustFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128f-robust.rsp", SPHINCSPlusParameters.sha2_128f },
            { "keypairs_ref_sha2-192f-robust.rsp", SPHINCSPlusParameters.sha2_192f },
            { "keypairs_ref_sha2-256f-robust.rsp", SPHINCSPlusParameters.sha2_256f },
            { "keypairs_ref_shake-128f-robust.rsp", SPHINCSPlusParameters.shake_128f },
            { "keypairs_ref_shake-192f-robust.rsp", SPHINCSPlusParameters.shake_192f },
            { "keypairs_ref_shake-256f-robust.rsp", SPHINCSPlusParameters.shake_256f },
            { "keypairs_ref_haraka-128f-robust.rsp", SPHINCSPlusParameters.haraka_128f },
            { "keypairs_ref_haraka-192f-robust.rsp", SPHINCSPlusParameters.haraka_192f },
            { "keypairs_ref_haraka-256f-robust.rsp", SPHINCSPlusParameters.haraka_256f },
        };
        private static readonly List<string> CreateSignedTestVectorFileNamesRobustFast = new List<string>(CreateSignedRobustFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CreateSignedRobustSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128s-robust.rsp", SPHINCSPlusParameters.sha2_128s },
            { "keypairs_ref_sha2-192s-robust.rsp", SPHINCSPlusParameters.sha2_192s },
            { "keypairs_ref_sha2-256s-robust.rsp", SPHINCSPlusParameters.sha2_256s },
            { "keypairs_ref_shake-128s-robust.rsp", SPHINCSPlusParameters.shake_128s },
            { "keypairs_ref_shake-192s-robust.rsp", SPHINCSPlusParameters.shake_192s },
            { "keypairs_ref_shake-256s-robust.rsp", SPHINCSPlusParameters.shake_256s },
            { "keypairs_ref_haraka-128s-robust.rsp", SPHINCSPlusParameters.haraka_128s },
            { "keypairs_ref_haraka-192s-robust.rsp", SPHINCSPlusParameters.haraka_192s },
            { "keypairs_ref_haraka-256s-robust.rsp", SPHINCSPlusParameters.haraka_256s },
        };
        private static readonly List<string> CreateSignedTestVectorFileNamesRobustSlow = new List<string>(CreateSignedRobustSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CreateSignedSimpleFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128f-simple.rsp", SPHINCSPlusParameters.sha2_128f_simple },
            { "keypairs_ref_sha2-192f-simple.rsp", SPHINCSPlusParameters.sha2_192f_simple },
            { "keypairs_ref_sha2-256f-simple.rsp", SPHINCSPlusParameters.sha2_256f_simple },
            { "keypairs_ref_shake-128f-simple.rsp", SPHINCSPlusParameters.shake_128f_simple },
            { "keypairs_ref_shake-192f-simple.rsp", SPHINCSPlusParameters.shake_192f_simple },
            { "keypairs_ref_shake-256f-simple.rsp", SPHINCSPlusParameters.shake_256f_simple },
            { "keypairs_ref_haraka-128f-simple.rsp", SPHINCSPlusParameters.haraka_128f_simple },
            { "keypairs_ref_haraka-192f-simple.rsp", SPHINCSPlusParameters.haraka_192f_simple },
            { "keypairs_ref_haraka-256f-simple.rsp", SPHINCSPlusParameters.haraka_256f_simple },
        };
        private static readonly List<string> CreateSignedTestVectorFileNamesSimpleFast = new List<string>(CreateSignedSimpleFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CreateSignedSimpleSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128s-simple.rsp", SPHINCSPlusParameters.sha2_128s_simple },
            { "keypairs_ref_sha2-192s-simple.rsp", SPHINCSPlusParameters.sha2_192s_simple },
            { "keypairs_ref_sha2-256s-simple.rsp", SPHINCSPlusParameters.sha2_256s_simple },
            { "keypairs_ref_shake-128s-simple.rsp", SPHINCSPlusParameters.shake_128s_simple },
            { "keypairs_ref_shake-192s-simple.rsp", SPHINCSPlusParameters.shake_192s_simple },
            { "keypairs_ref_shake-256s-simple.rsp", SPHINCSPlusParameters.shake_256s_simple },
            { "keypairs_ref_haraka-128s-simple.rsp", SPHINCSPlusParameters.haraka_128s_simple },
            { "keypairs_ref_haraka-192s-simple.rsp", SPHINCSPlusParameters.haraka_192s_simple },
            { "keypairs_ref_haraka-256s-simple.rsp", SPHINCSPlusParameters.haraka_256s_simple },
        };
        private static readonly List<string> CreateSignedTestVectorFileNamesSimpleSlow = new List<string>(CreateSignedSimpleSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CheckSignedRobustFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128f-robust.rsp", SPHINCSPlusParameters.sha2_128f },
            { "keypairs_ref_sha2-192f-robust.rsp", SPHINCSPlusParameters.sha2_192f },
            { "keypairs_ref_sha2-256f-robust.rsp", SPHINCSPlusParameters.sha2_256f },
            { "keypairs_ref_shake-128f-robust.rsp", SPHINCSPlusParameters.shake_128f },
            { "keypairs_ref_shake-192f-robust.rsp", SPHINCSPlusParameters.shake_192f },
            { "keypairs_ref_shake-256f-robust.rsp", SPHINCSPlusParameters.shake_256f },
            { "keypairs_ref_haraka-128f-robust.rsp", SPHINCSPlusParameters.haraka_128f },
            { "keypairs_ref_haraka-192f-robust.rsp", SPHINCSPlusParameters.haraka_192f },
            { "keypairs_ref_haraka-256f-robust.rsp", SPHINCSPlusParameters.haraka_256f },
        };
        private static readonly List<string> CheckSignedTestVectorFileNamesRobustFast = new List<string>(CheckSignedRobustFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CheckSignedRobustSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128s-robust.rsp", SPHINCSPlusParameters.sha2_128s },
            { "keypairs_ref_sha2-192s-robust.rsp", SPHINCSPlusParameters.sha2_192s },
            { "keypairs_ref_sha2-256s-robust.rsp", SPHINCSPlusParameters.sha2_256s },
            { "keypairs_ref_shake-128s-robust.rsp", SPHINCSPlusParameters.shake_128s },
            { "keypairs_ref_shake-192s-robust.rsp", SPHINCSPlusParameters.shake_192s },
            { "keypairs_ref_shake-256s-robust.rsp", SPHINCSPlusParameters.shake_256s },
            { "keypairs_ref_haraka-128s-robust.rsp", SPHINCSPlusParameters.haraka_128s },
            { "keypairs_ref_haraka-192s-robust.rsp", SPHINCSPlusParameters.haraka_192s },
            { "keypairs_ref_haraka-256s-robust.rsp", SPHINCSPlusParameters.haraka_256s },
        };
        private static readonly List<string> CheckSignedTestVectorFileNamesRobustSlow = new List<string>(CheckSignedRobustSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CheckSignedSimpleFast = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128f-simple.rsp", SPHINCSPlusParameters.sha2_128f_simple },
            { "keypairs_ref_sha2-192f-simple.rsp", SPHINCSPlusParameters.sha2_192f_simple },
            { "keypairs_ref_sha2-256f-simple.rsp", SPHINCSPlusParameters.sha2_256f_simple },
            { "keypairs_ref_shake-128f-simple.rsp", SPHINCSPlusParameters.shake_128f_simple },
            { "keypairs_ref_shake-192f-simple.rsp", SPHINCSPlusParameters.shake_192f_simple },
            { "keypairs_ref_shake-256f-simple.rsp", SPHINCSPlusParameters.shake_256f_simple },
            { "keypairs_ref_haraka-128f-simple.rsp", SPHINCSPlusParameters.haraka_128f_simple },
            { "keypairs_ref_haraka-192f-simple.rsp", SPHINCSPlusParameters.haraka_192f_simple },
            { "keypairs_ref_haraka-256f-simple.rsp", SPHINCSPlusParameters.haraka_256f_simple },
        };
        private static readonly List<string> CheckSignedTestVectorFileNamesSimpleFast = new List<string>(CheckSignedSimpleFast.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CheckSignedSimpleSlow = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "keypairs_ref_sha2-128s-simple.rsp", SPHINCSPlusParameters.sha2_128s_simple },
            { "keypairs_ref_sha2-192s-simple.rsp", SPHINCSPlusParameters.sha2_192s_simple },
            { "keypairs_ref_sha2-256s-simple.rsp", SPHINCSPlusParameters.sha2_256s_simple },
            { "keypairs_ref_shake-128s-simple.rsp", SPHINCSPlusParameters.shake_128s_simple },
            { "keypairs_ref_shake-192s-simple.rsp", SPHINCSPlusParameters.shake_192s_simple },
            { "keypairs_ref_shake-256s-simple.rsp", SPHINCSPlusParameters.shake_256s_simple },
            { "keypairs_ref_haraka-128s-simple.rsp", SPHINCSPlusParameters.haraka_128s_simple },
            { "keypairs_ref_haraka-192s-simple.rsp", SPHINCSPlusParameters.haraka_192s_simple },
            { "keypairs_ref_haraka-256s-simple.rsp", SPHINCSPlusParameters.haraka_256s_simple },
        };
        private static readonly List<string> CheckSignedTestVectorFileNamesSimpleSlow = new List<string>(CheckSignedSimpleSlow.Keys);

        private static readonly Dictionary<string, SPHINCSPlusParameters> CheckSignedAll = new Dictionary<string, SPHINCSPlusParameters>()
        {
            { "signed_csharp_ref_sha2-128f-robust.rsp", SPHINCSPlusParameters.sha2_128f },
            { "signed_csharp_ref_sha2-192f-robust.rsp", SPHINCSPlusParameters.sha2_192f },
            { "signed_csharp_ref_sha2-256f-robust.rsp", SPHINCSPlusParameters.sha2_256f },
            { "signed_csharp_ref_shake-128f-robust.rsp", SPHINCSPlusParameters.shake_128f },
            { "signed_csharp_ref_shake-192f-robust.rsp", SPHINCSPlusParameters.shake_192f },
            { "signed_csharp_ref_shake-256f-robust.rsp", SPHINCSPlusParameters.shake_256f },
            { "signed_csharp_ref_haraka-128f-robust.rsp", SPHINCSPlusParameters.haraka_128f },
            { "signed_csharp_ref_haraka-192f-robust.rsp", SPHINCSPlusParameters.haraka_192f },
            { "signed_csharp_ref_haraka-256f-robust.rsp", SPHINCSPlusParameters.haraka_256f },
            { "signed_csharp_ref_sha2-128s-robust.rsp", SPHINCSPlusParameters.sha2_128s },
            { "signed_csharp_ref_sha2-192s-robust.rsp", SPHINCSPlusParameters.sha2_192s },
            { "signed_csharp_ref_sha2-256s-robust.rsp", SPHINCSPlusParameters.sha2_256s },
            { "signed_csharp_ref_shake-128s-robust.rsp", SPHINCSPlusParameters.shake_128s },
            { "signed_csharp_ref_shake-192s-robust.rsp", SPHINCSPlusParameters.shake_192s },
            { "signed_csharp_ref_shake-256s-robust.rsp", SPHINCSPlusParameters.shake_256s },
            { "signed_csharp_ref_haraka-128s-robust.rsp", SPHINCSPlusParameters.haraka_128s },
            { "signed_csharp_ref_haraka-192s-robust.rsp", SPHINCSPlusParameters.haraka_192s },
            { "signed_csharp_ref_haraka-256s-robust.rsp", SPHINCSPlusParameters.haraka_256s },
            { "signed_csharp_ref_sha2-128f-simple.rsp", SPHINCSPlusParameters.sha2_128f_simple },
            { "signed_csharp_ref_sha2-192f-simple.rsp", SPHINCSPlusParameters.sha2_192f_simple },
            { "signed_csharp_ref_sha2-256f-simple.rsp", SPHINCSPlusParameters.sha2_256f_simple },
            { "signed_csharp_ref_shake-128f-simple.rsp", SPHINCSPlusParameters.shake_128f_simple },
            { "signed_csharp_ref_shake-192f-simple.rsp", SPHINCSPlusParameters.shake_192f_simple },
            { "signed_csharp_ref_shake-256f-simple.rsp", SPHINCSPlusParameters.shake_256f_simple },
            { "signed_csharp_ref_haraka-128f-simple.rsp", SPHINCSPlusParameters.haraka_128f_simple },
            { "signed_csharp_ref_haraka-192f-simple.rsp", SPHINCSPlusParameters.haraka_192f_simple },
            { "signed_csharp_ref_haraka-256f-simple.rsp", SPHINCSPlusParameters.haraka_256f_simple },
            { "signed_csharp_ref_sha2-128s-simple.rsp", SPHINCSPlusParameters.sha2_128s_simple },
            { "signed_csharp_ref_sha2-192s-simple.rsp", SPHINCSPlusParameters.sha2_192s_simple },
            { "signed_csharp_ref_sha2-256s-simple.rsp", SPHINCSPlusParameters.sha2_256s_simple },
            { "signed_csharp_ref_shake-128s-simple.rsp", SPHINCSPlusParameters.shake_128s_simple },
            { "signed_csharp_ref_shake-192s-simple.rsp", SPHINCSPlusParameters.shake_192s_simple },
            { "signed_csharp_ref_shake-256s-simple.rsp", SPHINCSPlusParameters.shake_256s_simple },
            { "signed_csharp_ref_haraka-128s-simple.rsp", SPHINCSPlusParameters.haraka_128s_simple },
            { "signed_csharp_ref_haraka-192s-simple.rsp", SPHINCSPlusParameters.haraka_192s_simple },
            { "signed_csharp_ref_haraka-256s-simple.rsp", SPHINCSPlusParameters.haraka_256s_simple },
        };
        private static readonly List<string> CheckSignedTestVectorFileNamesAll = new List<string>(CheckSignedAll.Keys);

        [TestCaseSource(nameof(CreateKeyPairsVectorFileNamesRobustFast))]
        [Parallelizable(ParallelScope.All)]
        public void CreateKeyPairsRobustFastVectors(string testVectorFile)
        {
            CreateKeyPairs(testVectorFile,createKeyPairsRobustFast);
        }

        [TestCaseSource(nameof(CreateKeyPairsVectorFileNamesRobustSlow))]
        [Parallelizable(ParallelScope.All)]
        public void CreateKeyPairsRobustSlowVectors(string testVectorFile)
        {
            CreateKeyPairs(testVectorFile,createKeyPairsRobustSlow);
        }

        [TestCaseSource(nameof(CreateKeyPairsVectorFileNamesSimpleFast))]
        [Parallelizable(ParallelScope.All)]
        public void CreateKeyPairsSimpleFastVectors(string testVectorFile)
        {
            CreateKeyPairs(testVectorFile,createKeyPairsSimpleFast);
        }

        [TestCaseSource(nameof(CreateKeyPairsVectorFileNamesSimpleSlow))]
        [Parallelizable(ParallelScope.All)]
        public void CreateKeyPairsSimpleSlowVectors(string testVectorFile)
        {
            CreateKeyPairs(testVectorFile,createKeyPairsSimpleSlow);
        }

        [TestCaseSource(nameof(CreateSignedTestVectorFileNamesRobustFast))]
        [Parallelizable(ParallelScope.All)]
        public void CreateSignedRobustFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CreateSigned,CreateSignedRobustFast);
        }

        [TestCaseSource(nameof(CreateSignedTestVectorFileNamesRobustSlow))]
        [Parallelizable(ParallelScope.All)]
        public void CreateSignedRobustSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CreateSigned,CreateSignedRobustSlow);
        }

        [TestCaseSource(nameof(CreateSignedTestVectorFileNamesSimpleFast))]
        [Parallelizable(ParallelScope.All)]
        public void CreateSignedSimpleFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CreateSigned,CreateSignedSimpleFast);
        }

        [TestCaseSource(nameof(CreateSignedTestVectorFileNamesSimpleSlow))]
        [Parallelizable(ParallelScope.All)]
        public void CreateSignedSimpleSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CreateSigned,CreateSignedSimpleSlow);
        }

        [TestCaseSource(nameof(CheckSignedTestVectorFileNamesRobustFast))]
        [Parallelizable(ParallelScope.All)]
        public void CheckSignedRobustFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CheckSigned,CheckSignedRobustFast);
        }

        [TestCaseSource(nameof(CheckSignedTestVectorFileNamesRobustSlow))]
        [Parallelizable(ParallelScope.All)]
        public void CheckSignedRobustSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CheckSigned,CheckSignedRobustSlow);
        }

        [TestCaseSource(nameof(CheckSignedTestVectorFileNamesSimpleFast))]
        [Parallelizable(ParallelScope.All)]
        public void CheckSignedSimpleFastVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CheckSigned,CheckSignedSimpleFast);
        }

        [TestCaseSource(nameof(CheckSignedTestVectorFileNamesSimpleSlow))]
        [Parallelizable(ParallelScope.All)]
        public void CheckSignedSimpleSlowVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CheckSigned,CheckSignedSimpleSlow);
        }

        [TestCaseSource(nameof(CheckSignedTestVectorFileNamesAll))]
        [Parallelizable(ParallelScope.All)]
        public void CheckSignedAllVectors(string testVectorFile)
        {
            RunTest(testVectorFile,"pqc.sphincsplus.interoperability.",CheckSigned,CheckSignedAll);
        }

        private static void CreateKeyPairs(string name, Dictionary<string, SPHINCSPlusParameters> paramDict)
        {
            Console.Error.WriteLine(name);

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
            SPHINCSPlusParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/sphincsplus/interoperability/"+name;

            string f1Contents = "";

            for (int i=0;i<100;i++){
                f1Contents += "count = "+i+"\n";
                random.NextBytes(seed,0,48);
                int messageLength = 33*(i+1); //keeping consistant messageLengths
                byte[] message = new byte[messageLength];
                f1Contents += "seed = " + Hex.ToHexString(seed)+"\n";
                SPHINCSPlusKeyPairGenerator keysGenerator = new SPHINCSPlusKeyPairGenerator();
                SPHINCSPlusKeyGenerationParameters generationParams = new SPHINCSPlusKeyGenerationParameters(random, parameters);
                keysGenerator.Init(generationParams);
                AsymmetricCipherKeyPair keys = keysGenerator.GenerateKeyPair();
                random.NextBytes(message,0,messageLength);
                SPHINCSPlusPublicKeyParameters publicKeyParams = (SPHINCSPlusPublicKeyParameters)keys.Public;
                SPHINCSPlusPrivateKeyParameters privateKeyParams = (SPHINCSPlusPrivateKeyParameters)keys.Private;
                byte[] finalPk = Arrays.CopyOfRange(publicKeyParams.GetEncoded(),publicKeyParams.GetParameters().GetEncoded().Length,publicKeyParams.GetEncoded().Length);
                byte[] finalSk = Arrays.CopyOfRange(privateKeyParams.GetEncoded(),privateKeyParams.GetParameters().GetEncoded().Length,privateKeyParams.GetEncoded().Length);
                
                f1Contents += "mlen = " +messageLength.ToString()+ "\n";
                f1Contents += "msg = " + Hex.ToHexString(message)+"\n";
                f1Contents += "pk = " + Hex.ToHexString(finalPk)+"\n";
                f1Contents += "sk = " + Hex.ToHexString(finalSk)+"\n";
                f1Contents +="\n";
            }
            File.WriteAllText(f1,f1Contents);
        }

        private static void CreateSigned(string name, IDictionary<string, string> buf,Dictionary<string, SPHINCSPlusParameters> paramDict)
        {
            String count = buf["count"];
            Console.Error.WriteLine(name+" "+count);
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] sk = Hex.Decode(buf["sk"]);
            byte[] message = Hex.Decode(buf["msg"]);
            
        
            byte[] seed = new byte[48];
            byte[] entropy_input = new byte[48];
            for (int i=0;i<48;i++){
                entropy_input[i]=Convert.ToByte(i);
            }

            SPHINCSPlusParameters parameters = paramDict[name];
            string f1 = "../../../data/pqc/sphincsplus/interoperability/signed_csharp_"+name.Substring("keypairs_ref_".Length,name.Length-"keypairs_ref_".Length);

            string f1Contents = "";
            if (count=="0"){
                File.WriteAllText(f1,f1Contents);
            }
  
            f1Contents += "count = "+buf["count"]+"\n";
            f1Contents += "pk = " + buf["pk"] + "\n";

            NistSecureRandom random = new NistSecureRandom(entropy_input,null);
            random.NextBytes(seed,0,48);
            Console.Error.WriteLine(Hex.ToHexString(pk));
            SPHINCSPlusPrivateKeyParameters privateKeyParams = new SPHINCSPlusPrivateKeyParameters(parameters,sk);
            
            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

            FixedSecureRandom.Source[] s1 = { new FixedSecureRandom.Source(seed) };
            signer.Init(true, new ParametersWithRandom(privateKeyParams, new FixedSecureRandom(s1)));

            byte[] sigGenerated = signer.GenerateSignature(message);
            byte[] attachedSig = Arrays.Concatenate(sigGenerated, message);


            f1Contents += "mlen = " + buf["mlen"] + "\n";
            f1Contents += "msg = " + buf["msg"] + "\n";
            f1Contents += "smlen = " + attachedSig.Length.ToString() + "\n";
            f1Contents += "sm = " + Hex.ToHexString(attachedSig) + "\n";
            f1Contents +="\n";

            File.AppendAllText(f1,f1Contents);
        }

        private static void CheckSigned(string name, IDictionary<string, string> buf,Dictionary<string, SPHINCSPlusParameters> paramDict)
        {
            String count = buf["count"];
            Console.Error.WriteLine(name+" "+count);
            byte[] pk = Hex.Decode(buf["pk"]);
            byte[] sm = Hex.Decode(buf["sm"]);
            byte[] message = Hex.Decode(buf["msg"]);
            int messageLen = int.Parse(buf["mlen"]);
            int smessageLen = int.Parse(buf["smlen"]);
            
            SPHINCSPlusParameters parameters = paramDict[name];
            
            SPHINCSPlusPublicKeyParameters publicKeyParams = new SPHINCSPlusPublicKeyParameters(parameters,pk);
            
            SPHINCSPlusSigner signer = new SPHINCSPlusSigner();

            signer.Init(false, publicKeyParams);

            byte[] smWithoutMessage = Arrays.CopyOfRange(sm,0,smessageLen-messageLen);
            bool verified = signer.VerifySignature(message,smWithoutMessage);

            Assert.True(verified, name + " " + count + ": signature verify");
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