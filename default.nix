with import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/5c211b47aeadcc178c5320afd4e74c7eed5c389f.tar.gz") {};

let
	cryptowrapper = stdenv.mkDerivation {
		pname = "cryptowrapper";
		version = "0.1.0";
		propagatedBuildInputs = [ openssl ];
		src = ./cryptowrapper;

		meta = with lib; {
			homepage = "https://github.com/watsonkp/cryptopals-python";
			description = "Library simplifying the use of a few OpenSSL functions.";
		};
	};
	gmpwrapper = stdenv.mkDerivation {
		pname = "gmpwrapper";
		version = "0.1.0";
		propagatedBuildInputs = [ gmp ];
		src = ./gmpwrapper;

		meta = with lib; {
			homepage = "https://github.com/watsonkp/cryptopals-python";
			description = "Library simplifying the use of a few GNU Multiple Precision Arithmetic Library functions.";
		};
	};
	in python310.pkgs.buildPythonPackage rec {
		pname = "cryptopals";
		version = "0.37.0";
		format = "pyproject";
		src = ./.;

		propagatedBuildInputs = [ cryptowrapper gmpwrapper ];

		# WARNING: This feels absolutely disgusting.
                # ctypes runtime loading of libraries doesn't play well with nix.
                # https://github.com/nixos/nixpkgs/issues/7307
                # https://discourse.nixos.org/t/screenshot-with-mss-in-python-says-no-x11-library/14534/4
                prePatch = ''
                        sed -i 's|lib${cryptowrapper.name}.so|${lib.makeLibraryPath [ cryptowrapper ]}/lib${cryptowrapper.name}.so|' src/sullied_cryptography_testing/cryptowrapper.py
                        sed -i 's|lib${gmpwrapper.name}.so|${lib.makeLibraryPath [ gmpwrapper ]}/lib${gmpwrapper.name}.so|' src/sullied_cryptography_testing/gmpwrapper.py
                '';

		doCheck = true;
		checkInputs = [ cryptowrapper gmpwrapper python310.pkgs.pytest ];
		checkPhase = "pytest --junitxml=$out/test-results.xml";
		meta = {
			homepage = "https://github.com/watsonkp/cryptopals-python";
			description = "Tools to test Cryptography inspired by CTF challenges";
		};
	}
