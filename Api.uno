using Uno;
using Uno.Collections;
using Uno.Text;
using Fuse;
using Fuse.Scripting;
using Fuse.Reactive;

using Community.Cryptography;
namespace Community
{

	public class Api : NativeModule
	{
		private static string _appSalt = "DEF_SALT";
		private static string _appPepper = "DEF_PEPPER";
		public Api()
		{
			AddMember(new NativeFunction("getOTP",(NativeCallback)GetOneTimePassword));
			AddMember(new NativeFunction("hashPassword",(NativeCallback)HashPassword));
			AddMember(new NativeFunction("setAppSalt",(NativeCallback)SetAppSalt));
			AddMember(new NativeFunction("setAppPepper",(NativeCallback)SetAppPepper));
		}

		static object SetAppSalt(Context c, object[] args)
		{
			_appSalt = args[0].ToString();

			return null;
		}

		static object SetAppPepper(Context c, object[] args)
		{
			_appPepper = args[0].ToString();

			return null;
		}

		static object HashPassword(Context c, object[] args)
		{
			string salt = args[1].ToString();
			string pwd = args[0].ToString();
			return hashPwd(pwd, salt);
		}

		static object GetOneTimePassword(Context c, object[] args)
		{
			try{
				string challenge = args[1].ToString();
				int instance = int.Parse( args[0].ToString());
				OneTimePassword otp = new OneTimePassword(instance, _appSalt + challenge + _appPepper);
	            return otp.GetCurrent();

			}
			catch(Exception e)
			{
				debug_log e.Message;
				return "GetOneTimePassword Error: " + e.Message;
			} //catch

		} //GetEncryption

	    static string hashPwd (string password, string salt)
	    {
		      string salt_start = _appSalt + salt.ToLower ();

		      string salt_end = salt.ToLower()+ _appPepper;

		      // merge password and salt together
		      string sHashWithSalt = salt_start + password + salt_end;
		      // convert this merged value to a byte array
		      byte[] saltedHashBytes = Utf8.GetBytes (sHashWithSalt);
		      // use hash algorithm to compute the hash
		      var algorithm = new SHA256 ();
		      byte[] result = algorithm.ComputeHash (saltedHashBytes);
		      // return the has as a base 64 encoded string
		      return Base64.GetString (result).Replace ('/', '%');
	    }//hashPwd
	}
}
