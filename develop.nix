with import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/5c211b47aeadcc178c5320afd4e74c7eed5c389f.tar.gz") {};

# Run with 
# nix-shell release.nix

# Usage
# python3
# from sullied_cryptography_testing import cryptowrapper
# cryptowrapper.sha1(b'AAAABBBBCCCCDDDD')

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
	cryptopals = python310.pkgs.buildPythonPackage rec {
		pname = "cryptopals";
		version = "0.37.0";
		format = "pyproject";
		src = ./.;

		propagatedBuildInputs = [ cryptowrapper ];

		doCheck = true;
		checkInputs = [ cryptowrapper python310.pkgs.pytest ];
		checkPhase = "pytest";
		meta = {
			homepage = "https://github.com/watsonkp/cryptopals-python";
			description = "Tools to test Cryptography inspired by CTF challenges";
		};
	};
	pythonEnv = python310.withPackages (ps: [ cryptopals python310.pkgs.pytest ]);
in mkShell {
	packages = [
		pythonEnv
	];
}
