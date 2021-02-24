---
title: Install the Pinniped command-line tool
description: Download and set up the `pinniped` command-line tool on macOS, Linux, or Windows clients.
cascade:
  layout: docs
menu:
  docs:
    name: Install CLI
    weight: 10
    parent: howtos
---
The `pinniped` command-line tool is used to generate Pinniped-compatible kubeconfig files, and is also an important part of the Pinniped-based login flow.

It must be installed by administrators setting up a Pinniped cluster as well as by users accessing a Pinniped-enabled cluster.

## Install using Homebrew on macOS or Linux

Use [Homebrew](https://brew.sh/) to install from the Pinniped [tap](https://github.com/vmware-tanzu/homebrew-pinniped):

- `brew install vmware-tanzu/pinniped/pinniped-cli`

## Download binaries

Find the appropriate binary for your platform from the [latest release](https://github.com/vmware-tanzu/pinniped/releases/latest):

{{< buttonlink href="https://get.pinniped.dev/latest/pinniped-cli-darwin-amd64" >}}Download for macOS/amd64{{< buttonicon "download.png" >}}{{< /buttonlink >}}

{{< buttonlink href="https://get.pinniped.dev/latest/pinniped-cli-linux-amd64" >}}Download for Linux/amd64{{< buttonicon "download.png" >}}{{< /buttonlink >}}

{{< buttonlink href="https://get.pinniped.dev/latest/pinniped-cli-windows-amd64.exe" >}}Download for Windows/amd64{{< buttonicon "download.png" >}}{{< /buttonlink >}}

You should put the command-line tool somewhere on your `$PATH`, such as `/usr/local/bin` on macOS/Linux.
You'll also need to mark the file as executable.

To find specific versions or view all available platforms and architectures, visit the [releases page](https://github.com/vmware-tanzu/pinniped/releases/).

### Gatekeeper

If you are using macOS, you may get an error dialog when you first run `pinniped` that says `“pinniped” cannot be opened because the developer cannotbe verified`.
Cancel this dialog, open System Preferences, click Security & Privacy, and click the Allow Anyway button next to the Pinniped message.

Run the command again and another dialog appears saying `macOS cannot verify the developer of “pinniped”. Are you sure you want to open it?`.
Click Open to allow the command to proceed.

## Install a specific version via script

For example, to install v0.4.1 on Linux/amd64:

```sh
curl -Lso pinniped https://get.pinniped.dev/v0.4.1/pinniped-cli-linux-amd64 \
  && chmod +x pinniped \
  && sudo mv pinniped /usr/local/bin/pinniped
```

*Next, [install the Concierge]({{< ref "install-concierge.md" >}})!*
