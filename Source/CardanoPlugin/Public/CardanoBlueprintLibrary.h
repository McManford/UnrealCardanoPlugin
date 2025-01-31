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
static const cardano_account_derivation_path_t ACCOUNT_DERIVATION_PATH = {
    1852U | 0x80000000,
    1815U | 0x80000000,
    0U
};

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
    static void GenerateWallet(TArray<FString>& OutMnemonicWords, FString& OutAddress);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void RestoreWallet(const TArray<FString>& MnemonicWords, FString& OutAddress, const FString& Password = TEXT("password"));

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void GetAddressBalance(const FString& Address, FAddressBalance& OutBalance, const FOnBalanceResult& OnComplete);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static void SubmitTransactionWithKoios(const TArray<uint8>& TransactionBytes, const FString& KoiosApiEndpoint);

    UFUNCTION(BlueprintCallable, Category = "Cardano|Wallet")
    static TArray<uint8> BuildTransaction(
        const TArray<FTransactionInput>& Inputs,
        const FString& ReceiverAddress,
        int64 AmountLovelace,
        int64 FeeLovelace,
        int64 TTL, 
        const TArray<FString>& MnemonicWords);

    UFUNCTION(BlueprintCallable, Category = "Cardano")
    static void GetAddressUTXOs(const FString& Address, TArray<FUTxO>& OutUTxOs, const FOnUTxOsResult& OnComplete);

    UFUNCTION(BlueprintPure, Category = "Cardano|Math")
    static float LovelaceToAda(const int64 Lovelace);

    UFUNCTION(BlueprintPure, Category = "Cardano|Math")
    static int64 AdaToLovelace(const float Ada);

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
