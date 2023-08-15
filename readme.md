# What is this?

This is a simple notary service. It allows you to notarize a file, which can be used as proof that the document existed in its current state at the time the notarization was requested. The notarization does not prove authorship.

# How do I use it?

## To notarize a file

1. Click on the icon and select your file or drag and drop your file anywhere in the white area
2. The file will appear with a blue filename - click on it to download the notarization

You must keep both the file as it was when you notarized it as well as the notarization in order to verify it later. **Note** just opening the file can cause modifications that will cause it to fail verification! After notarizing a file, consider marking the file read-only or storing a copy somewhere you can't easily open it (like on a USB stick or uploaded to Google Drive or Dropbox).

## To verify a notarization

1. Click on the icon and select both the file that was notarized and the notarization
2. Once both files have loaded, the file that was notarized will show a green checkmark or a red cross indicating if the notarization is valid (the file hasn't changed)

# How trustworthy is this?

As far as

- you have no relation to the notary
- the notary seal ("private key") is not stolen or the notary software hijacked to make unauthorized notarizations with the same seal

the notarizations are trustworthy.

The seal is stored on a Yubikey hardware security module. This prevents extracting the seal from a computer, even if the computer is hacked.

In the case that the computer is hacked, it could be manipulated to making unauthorized notarizations which, once detected, would throw into doubt all previous and future notarizations made with the same seal - to avoid this the seal is replaced regularly. Once the seal is replaced no further notarizations can be made with that key (existing notarizations can be verified forever).

Notarizations are standard cryptographic signatures made following the PGP standard. You can verify it without this service using other PGP software. You'll need to get the signing public key, below:

# Seal public keys

- <x>
