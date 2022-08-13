#! /usr/bin/env nix-shell
#! nix-shell --pure -i bash -p "python310.withPackages (ps: [ ps.pytest ])"
#! nix-shell -I nixpkgs=https://github.com/NixOS/nixpkgs/archive/5c211b47aeadcc178c5320afd4e74c7eed5c389f.tar.gz
pytest --junitxml=results.xml
