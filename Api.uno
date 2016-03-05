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
/*
			ulong[] numbers = new ulong[]{
				0 ,120, 3391362420264868341, 8247344706571482433, 11170817084526286401
			}; 
			foreach(ulong n in numbers)
			{
				string shad = Sha1.GetSha1(n.ToString());
				debug_log(""+n +"====>" + shad);
				
			}
			*/
			OneTimePassword otp = new OneTimePassword(1, "test");
			debug_log("OTP: " + otp.GetCurrent());
			//debug_log(""+5 + "====>" + SHA512.rotateleft(5,2));
			/*
			var l =  long.Parse("1956300319");
			var rl = maskedrotateleft(ulong.Parse(l.ToString()),5,32);
			debug_log("ROTATE LEFT: "+l + "====>" + rl);
			l = long.Parse("721293358");
			rl = maskedrotateleft(ulong.Parse(l.ToString()),5,32);
			debug_log("ROTATE LEFT: "+l + "====>" + rl);
//*/

			//Tester.testAll();
			return null;
		}
    public static ulong maskedrotateleft(ulong n, int shiftwidth, int maskedBits) {
        if (maskedBits > 63)
            throw new InvalidOperationException("Masked Bits must be less than 64, found: " + maskedBits);
        ulong result = 0;
        int[] bytes = new int[64];
        int[] bytesOrig = new int[64];
        // clear array
        for (int i=0; i<64; i++) { bytes[i] = 0; };
        // set bytes
        for (int i=0; i<64; i++) {
          int byteval = ((n & (1ul<<i)) > 0) ? 1 : 0;
          bytes[63-i] = byteval;
          bytesOrig[63-i] = byteval;
        };

//*
        string s = "";
        for(int i=0; i<64; i++) {
          s = s + bytes[i].ToString();
        }
        debug_log "Bytes array:" + s;
//*/
        // shift left n places
        for (int i=0; i<=63; i++) {
          if (i+shiftwidth < bytes.Length)
            bytes[i] = bytesOrig[i+shiftwidth];
          else
            bytes[i] = bytesOrig[(i+shiftwidth)%bytes.Length];
        }
        for (int i=maskedBits-shiftwidth;i<maskedBits; i++)
        {
        	bytes[i+maskedBits] = bytes[i]; 
        }
//*        
        s = "";
        for(int i=0; i<64; i++) {
          s = s + bytes[i].ToString();
        }
        debug_log "Post Shift Bytes array:" + s;
//*/

        // reconstruct new ulong
        for (int i=64-maskedBits; i<64; i++) {
          result = result * 2 + bytes[i];
        }
        return result;
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
