# CardanoPlugin

A prototype plugin for integrating Cardano with Unreal Engine. This project is currently in an early development stage and aims to provide wallet and transaction functionalities. Can be used for potential token and NFT related projects within Unreal Engine.

## Features

### Wallet Management

- ✅ Generate a new wallet address from a **24-word mnemonic phrase** via cardano-c library.
- ✅ Restore a wallet address from an **existing 24-word mnemonic phrase** and password combination.
- ✅ Retrieve the **Lovelace and token balance** using the [Koios API](https://api.koios.rest) and [Ogmios](https://github.com/CardanoSolutions/ogmios).
- ✅ Mac, Android, iOS, and other platform libraries added.
  - Runtime: Tested on iPhone XS (iOS 18), AppleTV 4K (tvOS 18.3), and Android Galaxy S22 Ultra (Android 14).
  - Editor: Tested and supports Unreal Engine version 4.27 on Windows and MacOS.
- ✅ Example code using [cardano-wallet API service](https://github.com/cardano-foundation/cardano-wallet).
- ✅ **Multi-asset support** for sending Cardano based tokens, using Blockfrost API and cardano-c's example.

### Upcoming Features

- [ ] **Fee estimation and coin selection strategies**.

## Development

This project is built with **Unreal Engine** and **C++**, leveraging [Biglup's cardano-c library](https://github.com/Biglup/cardano-c) and tools. Currently tested and supports Unreal Engine version 4.27 on Windows and MacOS, should work with later versions but not tested yet. 

When using `AsyncSendTokensWithBlockfrost`, leave `CustomBaseUrl` blank to use Blockfrost's API endpoints. Its there in case you want to set up on clients without exposing your Blockfrost API keys.

## License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

## Support & Contributions

Contributions are welcome! Feel free to submit **pull requests** or open **issues** for feature requests and improvements.

## Donations

If you'd like to support this project, you can send funds to the following addresses:

- **ADA**: `addr1q9uyegwa79525uksahk80vdfyznchd6q2clcvgk3vcm3zdmcfjsamutg4fedpm0vw7c6jg983wm5q43lsc3dze3hzymsexkm3m`
- **BTC**: `33R6Mytrbew4uJ28ppC7QexHg36VAiBHJA`