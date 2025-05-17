#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "Http.h"
#include "Json.h"
#include "CardanoTypes.h"
#include <cardano/cardano.h>
#include <cardano/key_handlers/account_derivation_path.h>
#include "CardanoBlueprintLibrary.generated.h"

/**
 * Blueprint library for Cardano wallet and address generation.
 */

USTRUCT(BlueprintType)
struct FTransactionInput
{
    GENERATED_BODY()

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Cardano|Wallet")
    FString TxHash;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Cardano|Wallet")
    int32 TxIndex;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Cardano|Wallet")
    int64 Value;

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Cardano|Wallet")
    FString PaymentAddress;

    UPROPERTY(BlueprintReadWrite, Category = "TransactionInput")
    int32 AddressIndex;
};

USTRUCT(BlueprintType)
struct FTransactionOutput 
{
    GENERATED_BODY()

    UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Cardano|Wallet")
    FString Address;

	UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "Cardano|Wallet")
	int64 Value;
};

UCLASS()
class CARDANOPLUGIN_API UCardanoBlueprintLibrary : public UBlueprintFunctionLibrary
{
    GENERATED_BODY()

public:
    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void GenerateWallet(TArray<FString>& OutMnemonicWords, FString& OutAddress, const FString& Password = TEXT("password"));

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void RestoreWallet(const TArray<FString>& MnemonicWords, FString& OutAddress, FString& OutStakeAddress, const FString& Password = TEXT("password"));

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void EstimateTransactionFeeOffline(
        const TArray<FTokenTransfer>& Transfers,
        bool bIncludeMetadata,
        FTransactionFeeResult& OutResult);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void AsyncEstimateTransactionFeeOffline(
        const TArray<FTokenTransfer>& Transfers,
        bool bIncludeMetadata,
        const FOnFeeEstimationComplete& OnComplete);

    /**
    * Checks if a word is a valid BIP39 mnemonic word for Cardano wallets.
    * 
    * @param Word The word to validate
    * @return True if the word is in the BIP39 word list, false otherwise
    */
    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static bool IsValidMnemonicWord(const FString& Word);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static bool ParseMnemonicPhrase(const FString& Phrase, TArray<FString>& OutWords, FString& OutErrorMessage);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Koios")
    static void QueryBalanceWithKoios(const FString& Address, FAddressBalance& OutBalance, const FOnBalanceResult& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Koios")
    static void SubmitTransactionWithKoios(const TArray<uint8>& TransactionBytes, const FString& KoiosApiEndpoint);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Ogmios")
    static void QueryBalanceWithOgmios(const FString& OgmiosURL, const FString& Address, const FOnBalanceQueryComplete& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Auth")
    static void GetWalletNonceAsync(
        const FString& StakeAddress,
        const FString& UrlBase,
        const FString& WalletName,
        const FOnGetWalletNonceComplete& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Ogmios")
    static bool GetUtxosWithOgmios(
        const FString& Address,
        const FString& OgmiosURL,
        FAddressBalance& OutBalance,
        const FOnUTxOsResult& OnComplete);

    /**
    * Sends Lovelace (ADA) transaction using the Ogmios node interface.
    *
    * @param OgmiosURL The URL of the Ogmios JSON-RPC endpoint
    * @param ReceiverAddress The Cardano address that will receive the ADA
    * @param AmountLovelace The amount of Lovelace to send (1 ADA = 1,000,000 Lovelace)
    * @param MnemonicWords The 24-word mnemonic phrase for the sending wallet
    * @param Password The spending password for the wallet
    * @param OutResult [Out] Structure that will contain the transaction result details
    * @param OnComplete Delegate that will be called when the transaction completes (success or failure)
    * @return Returns true if the transaction was initiated successfully, false otherwise
    */
    UFUNCTION(BlueprintCallable, Category = "Cardano|Ogmios")
    static bool SendLovelaceWithOgmios(
        const FString& OgmiosURL,
        const FString& ReceiverAddress,
        int64 AmountLovelace,
        const TArray<FString>& MnemonicWords,
        const FString& Password,
        FTokenTransactionResult& OutResult,
        const FOnTransactionCompleted& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Ogmios")
    static bool SendTokensWithOgmios(
        const FString& OgmiosURL,
        const FString& ReceiverAddress,
        TMap<FString, int64> TokensToSend,
        const TArray<FString>& MnemonicWords,
        const FString& Password,
        FTokenTransactionResult& OutResult,
        const FOnTransactionCompleted& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Ogmios")
    static bool GetAssetUtxosByIdWithOgmios(
        const FString& Address,
        const FString& OgmiosURL,
        const TArray<FString>& AssetIds,
        FAddressBalance& OutBalance,
        const FOnUTxOsResult& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Blockfrost")
    static void AsyncCalculateTransactionFeeWithBlockfrost(
        const FString& BlockfrostApiKey, 
        ECardanoNetwork NetworkType,
        const TArray<FTokenTransfer>& Outputs, 
        const FString& SenderAddress,
        const FString& ReceiverAddress,
        const FOnFeeEstimationComplete& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Blockfrost")
    static void GetAddressBalanceWithBlockfrost(
        const FString& Address, 
        const FString& BlockfrostApiKey, 
        TMap<FString, FString>& OutTokenMap,
        TMap<FString, FString>& OutUnitMap,
        const FOnBalanceResult& OnComplete);


    UFUNCTION(BlueprintCallable, Category = "Cardano|Blockfrost")
    static void SendTokensWithBlockfrost(
        const FString& ReceiverAddress, 
        TMap<FString, int64> TokensToSend, 
        const FString& BlockfrostApiKey, 
        ECardanoNetwork NetworkType, 
        const TArray<FString>& MnemonicWords, 
        const FString& Password, 
        FTransactionResult& OutResult, 
        const FOnTransactionCompleted& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Blockfrost", meta = (DisplayName = "Async Send Tokens with Blockfrost"))
    static void AsyncSendTokensWithBlockfrost(
        const FString& ReceiverAddress,
        TMap<FString, int64> TokensToSend,
        const FString& BlockfrostApiKey,
        ECardanoNetwork NetworkType,
        const TArray<FString>& MnemonicWords,
        const FString& Password,
        FTransactionResult& OutResult,
        const FOnTransactionCompleted& OnComplete,
        const FString& CustomBaseUrl);

    /**
    * Sends Lovelace (ADA) to a specified address using the Blockfrost provider
    * @param ReceiverAddress - Destination address where funds will be sent
    * @param AmountLovelace - Amount of Lovelace to send (1 ADA = 1,000,000 Lovelace)
    * @param BlockfrostApiKey - Your Blockfrost API key
    * @param NetworkType - Network to use (Mainnet, Testnet, Preprod, or Preview)
    * @param MnemonicWords - Wallet mnemonic phrase (24 words)
    * @param Password - Wallet password
    * @param OutResult - Transaction result info (success, error message, transaction ID)
    * @param OnComplete - Callback when transaction is complete
    */
    UFUNCTION(BlueprintCallable, Category = "Cardano|Blockfrost")
    static void SendLovelaceWithBlockfrost(
        const FString& ReceiverAddress,
        int64 AmountLovelace,
        const FString& BlockfrostApiKey,
        ECardanoNetwork NetworkType,
        const TArray<FString>& MnemonicWords,
        const FString& Password,
        FTransactionResult& OutResult,
        const FOnTransactionCompleted& OnComplete);

    /**
    * Asynchronously sends Lovelace (ADA) to an address using the Blockfrost API.
    *
    * This function performs a Cardano transaction in a background thread to send ADA to a specified
    * address. It handles all aspects of the transaction including wallet creation, UTXO management,
    * transaction building, signing, submitting and confirming.
    * 
    * @param ReceiverAddress The Cardano address to send the Lovelace to
    * @param AmountLovelace The amount of Lovelace to send (1 ADA = 1,000,000 Lovelace)
    * @param BlockfrostApiKey Your Blockfrost API key
    * @param NetworkType The Cardano network to use (Mainnet, Preprod, etc.)
    * @param MnemonicWords The 24-word mnemonic for the sending wallet
    * @param Password The spending password for the wallet
    * @param OutResult [Out] The transaction result containing success status, transaction ID, and any error messages
    * @param OnComplete Delegate to be called when the transaction is complete
    * @param CustomBaseUrl Optional custom Blockfrost API base URL (leave empty to use the default)
    */
    UFUNCTION(BlueprintCallable, Category = "Cardano|Blockfrost", meta = (DisplayName = "Async Send Lovelace with Blockfrost"))
    static void AsyncSendLovelaceWithBlockfrost(
        const FString& ReceiverAddress,
        int64 AmountLovelace,
        const FString& BlockfrostApiKey,
        ECardanoNetwork NetworkType,
        const TArray<FString>& MnemonicWords,
        const FString& Password,
        FTransactionResult& OutResult,
        const FOnTransactionCompleted& OnComplete,
        const FString& CustomBaseUrl = TEXT(""));

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void RegisterWithWalletServer(
        const FString& WalletURL,
        const FString& Passphrase, 
        const TArray<FString>& MnemonicWords,
        const FOnWalletRegistrationComplete& OnComplete,
        EWalletRestorationMode RestorationMode = EWalletRestorationMode::FROM_GENESIS);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static bool SendADAWithWalletServer(
        const FString& ReceiverAddress,
        const FString& WalletURL,
        int64 AmountLovelace,
        int64 FeeLovelace,
        const FString& Password,
        FTokenTransactionResult& OutResult);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static bool SendTokensWithWalletServer(
        const FString& WalletURL, 
        const FString& ReceiverAddress, 
        const TArray<FTokenTransfer>& Transfers, 
        const FString& Passphrase,
        FTokenTransactionResult& OutResult);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    bool SendTokensAndADAWithWalletServer(
        const FString& WalletURL, 
        const FString& ReceiverAddress, 
        int64 AmountLovelace, 
        int64 FeeLovelace, 
        const TArray<FTokenTransfer>& Transfers, 
        const FString& Passphrase, 
        FTokenTransactionResult& OutResult);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    bool GetWalletServerNetInfo(
        const FString& WalletURL,
        const FOnNetworkInfoResult& OnComplete);

    UFUNCTION(BlueprintPure, Category = "Cardano|Math")
    static float LovelaceToAda(const int64 Lovelace);

    UFUNCTION(BlueprintPure, Category = "Cardano|Math")
    static int64 AdaToLovelace(const float Ada);

    UFUNCTION(BlueprintPure, Category = "Cardano|Math")
    static FString DecodeCardanoAssetName(const FString& HexEncodedAssetName);

    UFUNCTION(BlueprintPure, Category = "Cardano")
    static int64 ConvertDisplayAmountToRawUnits(const FString& Ticker, const FString& DisplayAmount);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Token Transfer")
    static void MergeTokenTransfers(const TArray<FTokenTransfer>& Transfers, TMap<FString, int64>& OutMergedMap);


    UFUNCTION(BlueprintCallable, Category = "Cardano")
    static TArray<FTransactionInput> ConvertUTxOsToInputs(const TArray<FUTxO>& UTxOs)
    {
        TArray<FTransactionInput> Inputs;
        for (const FUTxO& UTxO : UTxOs)
        {
            FTransactionInput Input;
            Input.TxHash = UTxO.TxHash;
            Input.TxIndex = UTxO.TxIndex;
            Input.Value = UTxO.Value;
            Inputs.Add(Input);
        
            UE_LOG(LogTemp, Log, TEXT("Converting UTXO to Input - Hash: %s, Index: %d, Value: %lld"),
                *Input.TxHash, Input.TxIndex, Input.Value);
        }
        return Inputs;
    }

private:
    static int32 GetPassphrase(byte_t* buffer, size_t buffer_len);

};
