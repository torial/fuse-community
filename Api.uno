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
			AddMember(new NativeFunction("hashPassword256",(NativeCallback)HashPassword));
			AddMember(new NativeFunction("hashPassword512",(NativeCallback)HashPassword512));
			AddMember(new NativeFunction("setAppSalt",(NativeCallback)SetAppSalt));
			AddMember(new NativeFunction("setAppPepper",(NativeCallback)SetAppPepper));
			AddMember(new NativeFunction("generateCodes",(NativeCallback)GenerateCodes));
		}

		static object GenerateCodes(Context c, object[] args)
		{
			ulong[] numbers = new ulong[]{
				0,120, 3391362420264868341, 8247344706571482433, 11170817084526286401
			}; 
			ulong divisor = 2 << 6;
			foreach(ulong n in numbers)
			{
				ulong altResult = Tester.shr2(n,6); //n;
				//for(int i=0;i<6;i++)
				//	altResult = altResult/2;
				debug_log(""+n +"====>" + (n >> 6) + " should be: " + (altResult));

			}

			Tester.testAll();
			return null;
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
			string pwd = args[0].ToString();
			if (args.Length > 1)
			{
				string salt = args[1].ToString();
				return hashPwd(pwd, salt);
			}
			else
			{
				return hashPwd(pwd);
			}
		}

		static object HashPassword512(Context c, object[] args)
		{
			string pwd = args[0].ToString();
			if (args.Length > 1)
			{
				string salt = args[1].ToString();
				return hashPwd512(pwd, salt);
			}
			else
			{
				return hashPwd512(pwd);
			}
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
		      //return Base64.GetString (result).Replace ('/', '%');
		      return BitConverter.ToHex(result);
	    }//hashPwd

	    static string hashPwd512 (string password, string salt)
	    {
		      string salt_start = _appSalt + salt.ToLower ();

		      string salt_end = salt.ToLower()+ _appPepper;

		      // merge password and salt together
		      string sHashWithSalt = salt_start + password + salt_end;
		      // convert this merged value to a byte array
		      byte[] saltedHashBytes = Utf8.GetBytes (sHashWithSalt);
		      // use hash algorithm to compute the hash
		      var algorithm = new SHA512 ();
		      byte[] result = algorithm.ComputeHash (saltedHashBytes);
		      // return the has as a base 64 encoded string
		      //return Base64.GetString (result).Replace ('/', '%');
		      return BitConverter.ToHex(result);
	    }//hashPwd512	    



	    static string hashPwd (string password)
	    {
		      byte[] saltedHashBytes = Utf8.GetBytes (password);
		      // use hash algorithm to compute the hash
		      var algorithm = new SHA256 ();
		      byte[] result = algorithm.ComputeHash (saltedHashBytes);
		      // return the has as a base 64 encoded string
		      //return Base64.GetString (result).Replace ('/', '%');
		      return BitConverter.ToHex(result);
	    }//hashPwd

	    static string hashPwd512 (string password)
	    {
		      byte[] saltedHashBytes = Utf8.GetBytes (password);
		      // use hash algorithm to compute the hash
		      var algorithm = new SHA512 ();
		      byte[] result = algorithm.ComputeHash (saltedHashBytes);
		      // return the has as a base 64 encoded string
		      //return Base64.GetString (result).Replace ('/', '%');
		      return BitConverter.ToHex(result);
	    }//hashPwd512	    

	}
}
