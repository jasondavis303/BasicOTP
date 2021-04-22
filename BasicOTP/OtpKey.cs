/*
 Based on: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */

using System;
using System.Text;
using System.Web;

namespace BasicOTP
{
    public class OtpKey
    {
        public AuthTypes AuthType { get; set; } = AuthTypes.TOTP;
        public string Issuer { get; set; }
        public string Account { get; set; }
        public string Secret { get; set; }
        public Algorithms Algorithm { get; set; } = Algorithms.SHA1;
        public uint Digits { get; set; } = 6;
        public ulong Counter { get; set; }
        public uint Period { get; set; } = 30;


        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendFormat("otpauth://{0}/", AuthType.ToString().ToLower());

            string label = string.IsNullOrWhiteSpace(Issuer) ? Account : $"{Issuer}:{Account}";
            sb.Append(HttpUtility.UrlEncode(label));
            
            sb.AppendFormat("?secret={0}", Secret);
            if (!string.IsNullOrWhiteSpace(Issuer))
                sb.AppendFormat("&issuer={0}", HttpUtility.UrlEncode(Issuer));
            
            if (Algorithm != Algorithms.SHA1)
                sb.AppendFormat("&algorithm={0}", Algorithm.ToString());
            
            if (Digits != 0 && Digits != 6)
                sb.AppendFormat("&digits={0}", Digits);
            
            if (AuthType == AuthTypes.HOTP)
                sb.AppendFormat("&counter={0}", Counter);
            
            if (Period != 0 && Period != 30)
                sb.AppendFormat("&period={0}", Period);

            return sb.ToString();
        }

        public Uri ToUri() => new Uri(ToString());


        public static string GenerateRandomSecret(uint length = 32)
        {
            const string ALLOWED = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            if (length == 0)
                throw new ArgumentOutOfRangeException(nameof(length));

            var rand = new Random();
            string ret = string.Empty;
            for (uint i = 0; i < length; i++)
                ret += ALLOWED[rand.Next(0, ALLOWED.Length)];  

            return ret;
        }
        
        public static OtpKey FromString(string uri) => FromUri(new Uri(uri));

        public static OtpKey FromUri(Uri uri)
        {
            var ret = new OtpKey
            {
                AuthType = uri.Authority.ToLowerInvariant() switch
                {
                    "totp" => AuthTypes.TOTP,
                    "hotp" => AuthTypes.HOTP,
                    _ => throw new Exception("Invalid uri:authority"),
                }
            };

            string label = HttpUtility.UrlDecode(uri.Segments[1]);
            if (label.Contains(":"))
            {
                string[] parts = label.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                ret.Issuer = parts[0];
                ret.Account = parts[1];
            }
            else
            {
                ret.Account = label;
            }

            var nvc = HttpUtility.ParseQueryString(uri.Query);
            foreach (var parmKey in nvc.AllKeys)
            {
                switch(parmKey.ToLowerInvariant())
                {
                    case "secret":
                        ret.Secret = nvc[parmKey];
                        break;

                    case "issuer":
                        ret.Issuer = nvc[parmKey];
                        break;

                    case "algorithm":
                        ret.Algorithm = nvc[parmKey].ToUpperInvariant() switch
                        {
                            "SHA1" => Algorithms.SHA1,
                            "SHA256" => Algorithms.SHA256,
                            "SHA512" => Algorithms.SHA512,
                            _ => throw new Exception("Invalid uri:algorithm"),
                        };
                        break;

                    case "digits":
                        if (!uint.TryParse(nvc[parmKey], out uint digits))
                            throw new Exception("Invalid uri:digits");
                        ret.Digits = digits;
                        break;

                    case "counter":
                        if (ret.AuthType != AuthTypes.HOTP)
                            throw new Exception("Invalid uri:counter");
                        if (!ulong.TryParse(nvc[parmKey], out ulong counter))
                            throw new Exception("Invalid uri:counter");
                        ret.Counter = counter;
                        break;

                    case "period":
                        if (!uint.TryParse(nvc[parmKey], out uint period))
                            throw new Exception("Invalid uri:period");
                        ret.Period = period;
                        break;

                    default:
                        throw new Exception($"Invalid uri:{parmKey}");
                }
            }


            return ret;
        }
    }
}
