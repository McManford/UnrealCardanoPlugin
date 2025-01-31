#pragma once

#include "CoreMinimal.h"
#include "CardanoWalletTypes.generated.h"

/**
 * Holds the data for a freshly created wallet:
 * - A set of mnemonic words (seed phrase)
 * - The derived payment address
 */
USTRUCT(BlueprintType)
struct FCardanoWalletInfo
{
    GENERATED_BODY()

    // The 24 words of the BIP39 seed phrase
    UPROPERTY(BlueprintReadOnly, Category="Cardano|Wallet")
    TArray<FString> MnemonicWords;

    // The bech32 payment address derived from the mnemonic
    UPROPERTY(BlueprintReadOnly, Category="Cardano|Wallet")
    FString PaymentAddress;
};

