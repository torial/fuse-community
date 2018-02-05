# fuse-community
Anything that is useful for developing on the platform made by FuseTools.com 


##Contents

Currently contains:

1.  An implementation of Sha1, HmacSha1, and OneTimePassword ported from http://www.codeproject.com/Articles/592275/OTP-One-Time-Password-Demystified
2.  An implementation of Sha256 ported from http://hashlib.codeplex.com/

In addition, it contains sample code for using the libraries.

## Usage
A Javascript API is available, and the usage of it is shown in the ExampleUsage.ux file.  To link the fuse project to the Community Fuse project make sure that the fuse-community.unoproj is included in your unoproj file like the following:

```
  "Projects": ["../fuse-community/fuse-community.unoproj"],
```

Then in your UX file, add a global reference to it:
```
		<Community.Api ux:Global="CommunityApi" />

```

And in your Javascript in the UX file:
```
			var community = require("CommunityApi");

```

You will likely want to set a salt and pepper for the App:
```
			community.setAppSalt("Lowry's");
			community.setAppPepper("Seasoned");

```

To get the SHA256 hash of a password:
```
			var hash = community.hashPassword(pwd,salt);
```

To get a one time password at a particular instance (ie the first, or the fifteenth)
```
			var firstOTP= community.getOTP(1, pwd); 
			var fifteenthOTP = community.getOTP(15,pwd);

```

## License
Unless otherwise noted on individual files, the license is BSD v2.0 : 

Copyright (c) 2015, Sean McKay
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
