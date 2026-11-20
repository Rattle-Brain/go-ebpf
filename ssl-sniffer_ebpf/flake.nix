{
  description = "Go + eBPF development environment for sslsniff";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          mkApp = name: description: text:
            pkgs.writeShellApplication {
              inherit name text;
              meta.description = description;
            };

          apps = [
            (mkApp "compile" "Generate eBPF bytecode and build stripped ./sslsniff binary" ''
              go generate ./...
              go build -ldflags "-s -w" -o sslsniff ./cmd
            '')
            (mkApp "cleanup" "Remove built ./sslsniff binary and generated eBPF artifacts" ''
              rm -f ./sslsniff
              find . -path ./.git -prune -o -type f \( -name '*_bpfeb.go' -o -name '*_bpfel.go' -o -name '*.o' \) -exec rm -f {} +
            '')
            (mkApp "sniff-list" "List hookable libraries without root privileges" ''
              ./sslsniff -list
            '')
            (mkApp "sniff" "Hook all supported libraries across all processes (accepts flags)" ''
              sudo ./sslsniff "$@"
            '')
            (mkApp "sniff-nss" "Trace NSS (Firefox-family) with one-line request output" ''
              sudo ./sslsniff -libs nss -v 0
            '')
            (mkApp "sniff-lw" "Trace librewolf NSS traffic including payload bodies" ''
              sudo ./sslsniff -libs nss -comm librewolf -v 2
            '')
            (mkApp "sniff-comm" "Filter by process/thread names (default: curl,python3)" ''
              sudo ./sslsniff -comm "''${1:-curl,python3}"
            '')
            (mkApp "sniff-pid" "Filter in-kernel by PID (default: 1234)" ''
              sudo ./sslsniff -pid "''${1:-1234}"
            '')
            (mkApp "sniff-hex" "Output raw hexdump of first 256 bytes per event" ''
              sudo ./sslsniff -hex -max 256
            '')
            (mkApp "sniff-lib" "Hook an extra shared library path (default: /opt/app/libssl.so.1.1)" ''
              sudo ./sslsniff -lib "''${1:-/opt/app/libssl.so.1.1}"
            '')
            (mkApp "sniff-raw" "Output raw event text without HTTP protocol decoding" ''
              sudo ./sslsniff -raw
            '')
          ];

          renderBannerLines = pkgs.lib.concatMapStringsSep "\n" (app:
            ''printf "  %-12s %s\n" ${pkgs.lib.escapeShellArg app.name} ${pkgs.lib.escapeShellArg app.meta.description}''
          ) apps;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go
              llvmPackages.clang-unwrapped
              llvm
              libbpf
              linuxHeaders
              bpftools
            ] ++ apps;

            # Unwrapped clang ignores NIX_CFLAGS_COMPILE; C_INCLUDE_PATH is read natively
            C_INCLUDE_PATH = "${pkgs.libbpf}/include:${pkgs.linuxHeaders}/include";
            BPF_CFLAGS = "-I${pkgs.libbpf}/include -I${pkgs.linuxHeaders}/include";

            shellHook = ''
              echo "================================================================================"
              echo "  sslsniff Go + eBPF Development Environment"
              echo "================================================================================"
              ${renderBannerLines}
              echo "================================================================================"

              go_ver=$(go version | awk '{print $3}' | sed 's/^go//')
              if [ "$(printf '%s\n' "1.25" "$go_ver" | sort -V | head -n1)" != "1.25" ]; then
                echo "WARNING: Go >= 1.25 required, found $go_ver" >&2
              fi

              kver=$(uname -r | cut -d'-' -f1)
              if [ "$(printf '%s\n' "5.8" "$kver" | sort -V | head -n1)" != "5.8" ]; then
                echo "WARNING: Host kernel >= 5.8 required for BPF ring buffer, running $kver" >&2
              fi
            '';
          };
        }
      );
    };
}