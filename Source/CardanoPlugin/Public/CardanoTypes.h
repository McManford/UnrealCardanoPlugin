#pragma once
#include "CoreMinimal.h"
#include "CardanoTypes.generated.h"

// Rest of your types remain the same
USTRUCT(BlueprintType)
struct FTokenBalance
{
    GENERATED_BODY()
    
    UPROPERTY(BlueprintReadOnly, Category = "Cardano")
    FString PolicyId;

    UPROPERTY(BlueprintReadOnly, Category = "Cardano")
    FString AssetId;
    
    UPROPERTY(BlueprintReadOnly, Category = "Cardano")
    FString AssetName;
    
    UPROPERTY(BlueprintReadOnly, Category = "Cardano")
    FString Quantity;
    
    UPROPERTY(BlueprintReadOnly, Category = "Cardano")
    FString DisplayName;
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

USTRUCT(BlueprintType)
struct FTokenTransfer
{
    GENERATED_BODY()
    UPROPERTY(EditDefaultsOnly, Category = "Cardano|Token Transfer")
    FString PolicyId;     // Policy ID for the token (leave empty for ADA)
    UPROPERTY(EditDefaultsOnly, Category = "Cardano|Token Transfer")
    FString AssetName;    // Asset name (leave empty for ADA)
    UPROPERTY(EditDefaultsOnly, Category = "Cardano|Token Transfer")
    int64 Amount;         // Amount to transfer (in Lovelace for ADA, token units for custom tokens)
};

USTRUCT(BlueprintType)
struct FTokenTransactionResult
{
   GENERATED_BODY()
   UPROPERTY(BlueprintReadOnly, Category = "Cardano|Transaction")
   bool bSuccess;    // Whether transaction was successful
   UPROPERTY(BlueprintReadOnly, Category = "Cardano|Transaction")
   FString TransactionId;  // Unique transaction identifier 
   UPROPERTY(BlueprintReadOnly, Category = "Cardano|Transaction")
   FString ErrorMessage;   // Detailed error information if transaction fails
};

// Define the network information struct
USTRUCT(BlueprintType)
struct FCardanoNetworkInfo
{
    GENERATED_BODY()

    // Sync progress percentage (0-100)
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    float SyncProgress;

    // Network identifier (e.g., mainnet or testnet)
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    FString NetworkId;

    // Node tip information
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    int32 NodeTipHeight;
    
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    int32 NodeTipSlot;
    
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    FString NodeTipEpoch;

    // Node era (e.g., "byron", "shelley", "allegra", etc.)
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    FString NodeEra;

    // Connection status
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    bool bIsConnected;

    // Error message if any
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Network")
    FString ErrorMessage;

    FCardanoNetworkInfo()
        : SyncProgress(0)
        , NodeTipHeight(0)
        , NodeTipSlot(0)
        , bIsConnected(false)
    {}
};

USTRUCT(BlueprintType)
struct FWalletRegistrationResponse
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadWrite, Category = "Cardano")
    bool bSuccess;

    UPROPERTY(BlueprintReadWrite, Category = "Cardano")
    FString ErrorMessage;

    UPROPERTY(BlueprintReadWrite, Category = "Cardano")
    FString WalletId;

    UPROPERTY(BlueprintReadWrite, Category = "Cardano")
    FAddressBalance Balance;
};

// Add this enum to your header file
UENUM(BlueprintType)
enum class EWalletRestorationMode : uint8
{
    FROM_GENESIS UMETA(DisplayName = "From Genesis"),
    FROM_TIP     UMETA(DisplayName = "From Tip"),
    FROM_BLOCK   UMETA(DisplayName = "From Specific Block")
};

USTRUCT(BlueprintType)
struct FOgmiosBalanceResponse
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadWrite, Category = "Cardano|Balance")
    bool bSuccess;

    UPROPERTY(BlueprintReadWrite, Category = "Cardano|Balance")
    FString ErrorMessage;

    UPROPERTY(BlueprintReadWrite, Category = "Cardano|Balance")
    FAddressBalance Balance;
};

UENUM(BlueprintType)
enum class ECardanoNetwork : uint8
{
    Mainnet UMETA(DisplayName = "Mainnet"),
    Testnet UMETA(DisplayName = "Testnet"),
    Preprod UMETA(DisplayName = "Preprod"),
    Preview UMETA(DisplayName = "Preview")
};

USTRUCT(BlueprintType)
struct FTransactionResult
{
    GENERATED_BODY()

    UPROPERTY(BlueprintReadWrite, Category = "Cardano|Transaction")
    bool bSuccess = false;

    UPROPERTY(BlueprintReadWrite, Category = "Cardano|Transaction")
    FString ErrorMessage;

    UPROPERTY(BlueprintReadWrite, Category = "Cardano|Transaction")
    FString TransactionId;
};

/**
 * Structure to hold the result of a transaction fee estimation
 */
USTRUCT(BlueprintType)
struct FTransactionFeeResult
{
    GENERATED_BODY()
    
    /** Whether the fee estimation was successful */
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Transaction")
    bool bSuccess;
    
    /** The estimated transaction fee in lovelace */
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Transaction")
    int64 EstimatedFee;
    
    /** Error message if fee estimation failed */
    UPROPERTY(BlueprintReadOnly, Category = "Cardano|Transaction")
    FString ErrorMessage;
    
    FTransactionFeeResult()
        : bSuccess(false)
        , EstimatedFee(0)
        , ErrorMessage(TEXT(""))
    {}
};

// Delegate for fee estimation completion
DECLARE_DYNAMIC_DELEGATE_OneParam(FOnFeeEstimationComplete, const FTransactionFeeResult&, Result);

// Change the regular delegate to a dynamic delegate
DECLARE_DYNAMIC_DELEGATE_OneParam(FOnTransactionCompleted, const FTransactionResult&, Result);
DECLARE_DYNAMIC_DELEGATE_OneParam(FOnBalanceQueryComplete, const FOgmiosBalanceResponse&, Response);
DECLARE_DYNAMIC_DELEGATE_OneParam(FOnNetworkInfoResult, const FCardanoNetworkInfo&, NetworkInfo);
DECLARE_DYNAMIC_DELEGATE_OneParam(FOnWalletRegistrationComplete, const FWalletRegistrationResponse&, Response);
DECLARE_DYNAMIC_DELEGATE_TwoParams(FOnUTxOsResult, bool, Success, const FString&, ErrorMessage);
DECLARE_DYNAMIC_DELEGATE_TwoParams(FOnBalanceResult, bool, Success, const FString&, ErrorMessage);