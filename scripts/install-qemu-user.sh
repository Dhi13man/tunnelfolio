#!/bin/sh
set -eu

# Ubuntu 24.04 still ships qemu-user-static as a real package. On Ubuntu 26.04
# that name is virtual (provided by qemu-user-binfmt), so apt refuses to install
# it, and the emulators are named qemu-aarch64 / qemu-arm rather than *-static.
sudo apt-get update
if ! sudo apt-get install --yes qemu-user-static; then
	sudo apt-get install --yes qemu-user qemu-user-binfmt
fi
