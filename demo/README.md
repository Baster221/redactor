# Demo documents

Synthetic fixtures used by `scripts/studionet_demo.mjs`. Every value here is fake:
`4111 1111 1111 1111` is the standard Visa test number, `GB82WEST12345698765432` is the
ISO 13616 example IBAN, and the names, addresses and keys are invented.

They exist as plain files so validators can fetch them over https during the live demo.
A real publisher would host the document at a private or unguessable location instead; the
contract only stores the link and the hash, never the text.
