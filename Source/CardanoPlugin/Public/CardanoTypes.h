#pragma once
#include "CoreMinimal.h"
#include "CardanoTypes.generated.h"

// Change the regular delegate to a dynamic delegate
DECLARE_DYNAMIC_DELEGATE_TwoParams(FOnUTxOsResult, bool, Success, const FString&, ErrorMessage);
DECLARE_DYNAMIC_DELEGATE_TwoParams(FOnBalanceResult, bool, Success, const FString&, ErrorMessage);

// Rest of your types remain the same
USTRUCT(BlueprintType)
struct FTokenBalance
{
    GENERATED_BODY()
    UPROPERTY(BlueprintReadOnly)
    FString PolicyId;
    UPROPERTY(BlueprintReadOnly) 
    FString AssetName;
    UPROPERTY(BlueprintReadOnly)
    FString Quantity;
};

USTRUCT(BlueprintType)
struct FAddressBalance 
{
    GENERATED_BODY()
    UPROPERTY(BlueprintReadOnly)
    int64 Lovelace = 0;
    UPROPERTY(BlueprintReadOnly)
    TArray<FTokenBalance> Tokens;
};

USTRUCT(BlueprintType)
struct FUTxO
{
    GENERATED_BODY()
    UPROPERTY(BlueprintReadWrite, Category = "UTxO")
    FString TxHash;
    UPROPERTY(BlueprintReadWrite, Category = "UTxO")
    int32 TxIndex;
    UPROPERTY(BlueprintReadWrite, Category = "UTxO")
    int64 Value;
};

USTRUCT(BlueprintType)
struct FUTxOResult
{
    GENERATED_BODY()
    UPROPERTY(BlueprintReadOnly)
    bool bSuccess;
    UPROPERTY(BlueprintReadOnly)
    FString Message;
};