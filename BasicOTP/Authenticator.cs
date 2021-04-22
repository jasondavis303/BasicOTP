using System;
using System.Net;
using System.Security.Cryptography;

namespace BasicOTP
{
    public static class Authenticator
    {
        private const long EPOCH_TICKS = 621355968000000000L;
        private const long SECOND_TICKS = 10000000L;

        private static long m_TimeOffset = 0;

        private static long CorrectedTicks => DateTime.UtcNow.Ticks - EPOCH_TICKS + m_TimeOffset;

        /// <summary>
        /// Get an OTP code
        /// </summary>
        public static string GetCode(OtpKey otpKey)
        {
            if (otpKey.AuthType == AuthTypes.TOTP)
            {
                long challenge = CorrectedTicks / (otpKey.Period * SECOND_TICKS);
                return GetCode(otpKey, (ulong)challenge);
            }
            else
            {
                return GetCode(otpKey, otpKey.Counter);
            }
        }


        /// <summary>
        /// Get remainint time before the current code will change
        /// </summary>
        public static TimeSpan GetRemainingTime(OtpKey otpKey)
        {
            if (otpKey.AuthType != AuthTypes.TOTP)
                throw new Exception("Remaining time not supported for non-TOTP authentication");

            long periodTicks = SECOND_TICKS * otpKey.Period;
            return TimeSpan.FromTicks(periodTicks - (CorrectedTicks % periodTicks) + SECOND_TICKS);
        }


        /// <summary>
        /// Check if the specified code is valid
        /// </summary>
        /// <param name="slidingWindow">How many periods before and after the current time to check</param>
        public static bool CheckCode(OtpKey otpKey, string code, uint slidingWindow = 0)
        {
            if (code == GetCode(otpKey))
                return true;

            if (slidingWindow == 0)
                return false;

            if (otpKey.AuthType == AuthTypes.TOTP)
            {
                long origOffset = m_TimeOffset;
                long ticks = TimeSpan.FromSeconds(otpKey.Period * slidingWindow).Ticks;

                m_TimeOffset = origOffset - ticks;
                bool ret = code == GetCode(otpKey);

                if (!ret)
                {
                    m_TimeOffset = origOffset + ticks;
                    ret = code == GetCode(otpKey);
                }

                m_TimeOffset = origOffset;
                return ret;
            }

            if (otpKey.AuthType == AuthTypes.HOTP)
            {
                ulong origCounter = otpKey.Counter;

                otpKey.Counter = origCounter - 1;
                bool ret = code == GetCode(otpKey);

                if (!ret)
                {
                    otpKey.Counter = origCounter + 1;
                    ret = code == GetCode(otpKey);
                }

                otpKey.Counter = origCounter;
                return ret;
            }

            return false;
        }


        /// <summary>
        /// If the current computer time is out of sync and generated codes are incorrect, this tries to compensate by checking the current time from google.com
        /// </summary>
        public static void SyncTime()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("http://www.google.com");
            request.Method = "GET";
            request.ContentType = "text/html";
            request.Timeout = 5000;

            using HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            if (response.StatusCode != HttpStatusCode.OK)
                throw new ApplicationException(string.Format("{0}: {1}", (int)response.StatusCode, response.StatusDescription));

            string headerdate = response.Headers["Date"];
            if (string.IsNullOrEmpty(headerdate) == false)
                if (DateTime.TryParse(headerdate, out DateTime dt))
                    m_TimeOffset = (dt - DateTime.Now).Ticks;
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


        
    }
}
