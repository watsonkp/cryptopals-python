with import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/5c211b47aeadcc178c5320afd4e74c7eed5c389f.tar.gz") {};

# echo $NIX_LDFLAGS | awk 'match($0, /\/nix\/store\/[a-zA-Z0-9]+-libcryptowrapper-1.0.0/){print substr($0, RSTART, RLENGTH)}'

stdenv.mkDerivation {
	pname = "libcryptowrapper";
	version = "0.1.0";
	src = ./.;
	propagatedBuildInputs = [ openssl ];
}
