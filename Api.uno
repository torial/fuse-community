using Uno;
using Uno.Collections;
using Uno.Text;
using Fuse;
using Fuse.Scripting;
using Fuse.Reactive;

using Community.Cryptography;
namespace NewsFeed
{
  class KlicklePwd
    {
        public static string HashPassword2 (string password, string salt_start)
        {
            salt_start = "%*KLI" + salt_start.ToLower () + "CKLE$^";
            int sub = salt_start.Length / 2 + 1;

            // merge password and salt together
            string sHashWithSalt = salt_start.Substring (0, sub) + password + salt_start.Substring (sub);
            // convert this merged value to a byte array
            byte[] saltedHashBytes = Utf8.GetBytes (sHashWithSalt);
            // use hash algorithm to compute the hash
            var algorithm = new SHA256 ();
            byte[] result = algorithm.ComputeHash (saltedHashBytes);
            // return the has as a base 64 encoded string
            return Base64.GetString (result).Replace ('/', '%');

        }
    }


	public class Utils : NativeModule
	{
		public Utils()
		{
			AddMember(new NativeFunction("getWeather",(NativeCallback)GetWeather));
			AddMember(new NativeFunction("getEncryption",(NativeCallback)GetEncryption));
			AddMember(new NativeFunction("hashPassword",(NativeCallback)HashPassword));
		}

		static object HashPassword(Context c, object[] args)
		{
			return KlicklePwd.HashPassword2(args[1].ToString(), args[0].ToString());
		}



		static object GetWeather(Context c, object[] args)
		{
			//for now just use the dummy weather data.  Eventually will either:
			//a) query the Weather service directly -- or use local cache if today's values already owned
            //b) have server query the service for select locales, and then app will make DB call
try{
	//return "";
		var bundleFile = import BundleFile("sampleWeather.json");
		var json = bundleFile.ReadAllText();
		return json;
		}
		catch(Exception e)
		{
			debug_log e.Message;
			return "ERROR: getWeather failed: " + e.Message;
		}
		}
	
//*
	static object GetEncryption(Context c, object[] args)
	{
		try{
			string challenge = "TEST of OTP";
			OneTimePassword otp = new OneTimePassword(1, "SOME SALT" + challenge + "SOME PEPPER");
            return otp.GetCurrent();

		}
		catch(Exception e)
		{
			debug_log e.Message;
			return "GetEncryption Error: " + e.Message;
		} //catch

	} //GetEncryption
//	*/
}
}
