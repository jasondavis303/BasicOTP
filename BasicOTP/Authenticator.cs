using System;
using System.Net;
using System.Security.Cryptography;

namespace BasicOTP
{
    public static class Authenticator
    {
        public static long TimeOffset { get; set; }


        public static string GetCode(OtpKey otpKey)
        {
            if (otpKey.AuthType == AuthTypes.TOTP)
            {
                TimeSpan ts = (DateTime.UtcNow.AddTicks(TimeOffset) - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc));
                long challenge = (long)ts.TotalSeconds / otpKey.Period;

                return GetCode(otpKey, (ulong)challenge);
            }
            else
            {
                return GetCode(otpKey, otpKey.Counter);
            }
        }

        private static string GetCode(OtpKey otpKey, ulong challengeValue)
        {
            ulong chlg = challengeValue;
            byte[] challenge = new byte[8];
            for (int j = 7; j >= 0; j--)
            {
                challenge[j] = (byte)((int)chlg & 0xff);
                chlg >>= 8;
            }

            var key = Base32Encoding.ToBytes(otpKey.Secret);
            for (int i = otpKey.Secret.Length; i < key.Length; i++)
                key[i] = 0;
            

            using var mac = GetHMAC(otpKey, key);
            var hash = mac.ComputeHash(challenge);

            // the last 4 bits of the mac say where the code starts
            int offset = hash[hash.Length - 1] & 0xf;

            // extract those 4 bytes
            byte[] bytes = new byte[4];
            Array.Copy(hash, offset, bytes, 0, 4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            uint fullcode = BitConverter.ToUInt32(bytes, 0) & 0x7fffffff;

            // we use the last 8 digits of this code in radix 10
            uint codemask = (uint)Math.Pow(10, otpKey.Digits);
            string format = new string('0', (int)otpKey.Digits);
            string code = (fullcode % codemask).ToString(format);

            return code;
        }

        public static bool CheckCode(OtpKey otpKey, string code, uint slidingWindow = 1)
        {
            if (code == GetCode(otpKey))
                return true;

            if (slidingWindow == 0)
                return false;

            if (otpKey.AuthType == AuthTypes.TOTP)
            {
                long origOffset = TimeOffset;
                long ticks = TimeSpan.FromSeconds(otpKey.Period * slidingWindow).Ticks;

                TimeOffset = origOffset - ticks;
                bool ret = code == GetCode(otpKey);

                if (!ret)
                {
                    TimeOffset = origOffset + ticks;
                    ret = code == GetCode(otpKey);
                }

                TimeOffset = origOffset;
                return ret;
            }
            
            if(otpKey.AuthType == AuthTypes.HOTP)
            {
                ulong origCounter = otpKey.Counter;

                otpKey.Counter = origCounter - 1;
                bool ret = code == GetCode(otpKey);

                if(!ret)
                {
                    otpKey.Counter = origCounter + 1;
                    ret = code == GetCode(otpKey);
                }

                otpKey.Counter = origCounter;
                return ret;
            }

            return false;
        }

        private static HMAC GetHMAC(OtpKey otpKey, byte[] key)
        {
            switch (otpKey.Algorithm)
            {
                case Algorithms.SHA1:
                    return new HMACSHA1(key);

                case Algorithms.SHA256:
                    return new HMACSHA256(key);

                case Algorithms.SHA512:
                    return new HMACSHA512(key);

                default:
                    throw new Exception("Unknown algorighm");
            }
        }


        public static void SyncTime()
        {
            try
            {
                // we use the Header response field from a request to www.google.come
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://www.google.com");
                request.Method = "GET";
                request.ContentType = "text/html";
                request.Timeout = 5000;

                // get response
                using HttpWebResponse response = (HttpWebResponse)request.GetResponse();

                // OK?
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new ApplicationException(string.Format("{0}: {1}", (int)response.StatusCode, response.StatusDescription));

                string headerdate = response.Headers["Date"];
                if (string.IsNullOrEmpty(headerdate) == false)
                    if (DateTime.TryParse(headerdate, out DateTime dt))
                        TimeOffset = (dt - DateTime.Now).Ticks;
            }
            catch { }
        }

    }
}
