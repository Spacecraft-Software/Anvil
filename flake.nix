# SPDX-License-Identifier: GPL-3.0-or-later
# Nix flake for Anvil — pure-Rust SSH stack for Git tooling.
#
# Anvil is a library; this flake exposes a development shell.  Consumers
# depend on the published `anvil-ssh` crate from crates.io.
#
# Usage:
#   nix develop                       # enter the development shell
{
  description = "Pure-Rust SSH stack for Git tooling: transport, keys, signing, agent";

  inputs = {
    nixpkgs.url     = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          name = "anvil-dev";

          nativeBuildInputs = with pkgs; [
            # Rust toolchain via rustup so developers can pin versions freely
            # (rust-toolchain.toml pins the channel).
            rustup

            # Required by aws-lc-rs for assembly pre-processing.  Non-FIPS
            # builds do NOT require cmake or go.
            perl

            # C toolchain for linking.
            gcc

            # Optional: strip release artefacts.
            binutils

            git
          ];

          # Override NixOS-injected CFLAGS that break aws-lc-rs's C build:
          # the stdenv injects `-flto=auto`, which produces GCC LTO IR objects
          # the Rust linker can't resolve.  RUSTFLAGS is left to flow through
          # from the ambient environment so host-level CPU targeting takes
          # effect.
          CFLAGS = "-march=native -O2 -pipe";

          shellHook = ''
            echo "anvil dev shell ready. Run: cargo build --release"
          '';
        };
      }
    );
}
