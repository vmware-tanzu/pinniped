#!/usr/bin/env bash

# Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -exuo pipefail

# Start in the user's home directory.
cd

# Install brew pre-reqs documented at https://docs.brew.sh/Homebrew-on-Linux#requirements
sudo apt-get update && sudo sudo apt-get install build-essential procps curl file git -y
# Brew installer command from https://brew.sh. Note that CI=1 turns off an interactive prompt.
CI=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# The installer prints more instructions. It advises you to add brew to profile and install gcc.
echo 'eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' >>$HOME/.profile
eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
brew install gcc

# Install go.
brew install go
# On linux go really wants gcc5 to also be installed for some reason.
brew install gcc@5
# Get the Go linter.
go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.1

# Install and configure zsh and plugins.
brew install zsh zsh-history-substring-search
brew install fasd fzf
/home/linuxbrew/.linuxbrew/opt/fzf/install --all --no-bash --no-fish
# Install https://ohmyz.sh
export PATH=$PATH:/home/linuxbrew/.linuxbrew/bin
CHSH=no RUNZSH=no KEEP_ZSHRC=yes sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
# Install some plugins.
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$HOME"/.oh-my-zsh/custom/themes/powerlevel10k
git clone https://github.com/zsh-users/zsh-autosuggestions "$HOME"/.oh-my-zsh/custom/plugins/zsh-autosuggestions
git clone https://github.com/TamCore/autoupdate-oh-my-zsh-plugins "$HOME"/.oh-my-zsh/plugins/autoupdate
git clone https://github.com/zdharma-continuum/fast-syntax-highlighting.git "$HOME"/.oh-my-zsh/custom/plugins/fast-syntax-highlighting
# Get decent .zshrc and .p10k.zsh files.
curl -fsSL https://gist.githubusercontent.com/cfryanr/c84ca9e3fe519b5a7f07426ecc7e3a7c/raw >"$HOME"/.zshrc
curl -fsSL https://gist.githubusercontent.com/cfryanr/3e55b770b9be485bd8671377ce04a3f1/raw >"$HOME"/.p10k.zsh
# Change the user's default shell.
sudo chsh -s /home/linuxbrew/.linuxbrew/bin/zsh "$USER"

# Get some other useful config files.
curl -fsSL https://gist.githubusercontent.com/cfryanr/153e167a1f2c20934fbc4dc32bbec8f2/raw >"$HOME"/.gitconfig
curl -fsSL https://gist.githubusercontent.com/cfryanr/80ada8af9a78f08b368327401ea80b6c/raw >"$HOME"/.git-authors

# Install other useful packages.
brew tap homebrew/command-not-found
brew tap vmware-tanzu/carvel
brew install ytt kbld kapp imgpkg kwt vendir
brew install git git-duet/tap/git-duet pre-commit gh
brew install k9s kind kubectl kubectx stern
brew install exa acarl005/homebrew-formulas/ls-go ripgrep procs bat tokei git-delta dust fd httpie chroma
brew install watch htop wget
brew install jesseduffield/lazydocker/lazydocker ctop dive
brew install jq yq
brew install grip
brew install aws-iam-authenticator
brew install step cfssl
brew install nmap
sudo apt-get install apache2-utils rsync -y

# Install Chrome
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb -y
rm ./google-chrome-stable_current_amd64.deb
google-chrome --version
mkdir "$HOME"/bin

# Install docker according to procedure from https://docs.docker.com/engine/install/debian/
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release -y
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io -y
sudo usermod -aG docker "$USER"
sudo systemctl enable docker.service
sudo systemctl enable containerd.service

# Set up the Pinniped repo
mkdir workspace
pushd workspace
ssh-keyscan -H github.com >> $HOME/.ssh/known_hosts
# This assumes that you used `--ssh-flag=-A` when using `gcloud compute ssh` to log in to the host,
# which will forward your ssh identities.
git clone git@github.com:vmware-tanzu/pinniped.git
pushd pinniped
pre-commit install
popd
popd

set +x
echo
echo "Successfully installed deps!"
