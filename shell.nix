# SPDX-License-Identifier: GPL-3.0-or-later
# Development shell for users without Nix flakes enabled.
#
# Usage:
#   nix-shell              # enter interactively
#   nix-shell --run '...'  # run a single command
#
# If you have flake support enabled, prefer:
#   nix develop
{ pkgs ? import <nixpkgs> { } }:

pkgs.mkShell {
  name = "anvil-dev";

  nativeBuildInputs = with pkgs; [
    rustup
    perl
    gcc
    binutils
    git
  ];

  CFLAGS = "-march=native -O2 -pipe";

  shellHook = ''
    echo "anvil dev shell ready. Run: cargo build --release"
  '';
}
