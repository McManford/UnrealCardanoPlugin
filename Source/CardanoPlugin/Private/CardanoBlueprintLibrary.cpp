#include "CardanoBlueprintLibrary.h"
#include "CoreMinimal.h"
#include <cardano/bip39.h>
#include <cardano/error.h>
#include <cardano/buffer.h>
#include <cardano/typedefs.h>
#include <cardano/address/address.h>
#include <cardano/witness_set/vkey_witness.h>
#include <cardano/witness_set/vkey_witness_set.h>
#include <cardano/crypto/bip32_private_key.h>
#include <cardano/crypto/ed25519_private_key.h>
#include <cardano/crypto/ed25519_public_key.h>
#include <cardano/crypto/ed25519_signature.h>
#include <cardano/transaction_body/transaction_body.h>
#include <cardano/transaction/transaction.h>
#include <cardano/address/base_address.h>
#include <cardano/key_handlers/software_secure_key_handler.h>
#include "cardano/key_handlers/secure_key_handler.h"
#include "Misc/Paths.h"
#include "Misc/OutputDeviceDebug.h"
#include <cardano/cardano.h>
#include <sodium.h>

// C 
static const cardano_account_derivation_path_t ACCOUNT_DERIVATION_PATH = {
    1852U | 0x80000000,
    1815U | 0x80000000,
    0U
};

static const cardano_derivation_path_t SIGNER_DERIVATION_PATH = {
  1852U | 0x80000000,
  1815U | 0x80000000,
  0U,
  0U,
  0U
};

cardano_credential_t* create_credential(cardano_ed25519_public_key_t* public_key)
{
    cardano_blake2b_hash_t* hash = nullptr;
    cardano_error_t result = cardano_ed25519_public_key_to_hash(public_key, &hash);

    if (result != CARDANO_SUCCESS) {
        return nullptr;
    }

    cardano_credential_t* credential = nullptr;
    result = cardano_credential_new(hash, CARDANO_CREDENTIAL_TYPE_KEY_HASH, &credential);
    cardano_blake2b_hash_unref(&hash);

    return credential;
}

cardano_address_t* create_address_from_derivation_paths(
    cardano_secure_key_handler_t* key_handler,
    cardano_account_derivation_path_t account_path,
    uint32_t payment_index,
    uint32_t stake_key_index)
{
    cardano_bip32_public_key_t* root_public_key = nullptr;
    cardano_error_t result = cardano_secure_key_handler_bip32_get_extended_account_public_key(
        key_handler, account_path, &root_public_key);

    if (result != CARDANO_SUCCESS) {
        return nullptr;
    }

    const uint32_t payment_key_derivation_path[] = {
        CARDANO_CIP_1852_ROLE_EXTERNAL,
        payment_index
    };

    const uint32_t stake_key_derivation_path[] = {
        CARDANO_CIP_1852_ROLE_STAKING,
        stake_key_index
    };

    cardano_bip32_public_key_t* payment_public_key = nullptr;
    cardano_bip32_public_key_t* stake_public_key = nullptr;
    cardano_ed25519_public_key_t* payment_key = nullptr;
    cardano_ed25519_public_key_t* stake_key = nullptr;

    result = cardano_bip32_public_key_derive(root_public_key, payment_key_derivation_path, 2, &payment_public_key);
    if (result != CARDANO_SUCCESS) {
        cardano_bip32_public_key_unref(&root_public_key);
        return nullptr;
    }

    result = cardano_bip32_public_key_derive(root_public_key, stake_key_derivation_path, 2, &stake_public_key);
    if (result != CARDANO_SUCCESS) {
        cardano_bip32_public_key_unref(&root_public_key);
        cardano_bip32_public_key_unref(&payment_public_key);
        return nullptr;
    }

    result = cardano_bip32_public_key_to_ed25519_key(payment_public_key, &payment_key);
    if (result != CARDANO_SUCCESS) {
        cardano_bip32_public_key_unref(&root_public_key);
        cardano_bip32_public_key_unref(&payment_public_key);
        cardano_bip32_public_key_unref(&stake_public_key);
        return nullptr;
    }

    result = cardano_bip32_public_key_to_ed25519_key(stake_public_key, &stake_key);
    if (result != CARDANO_SUCCESS) {
        cardano_bip32_public_key_unref(&root_public_key);
        cardano_bip32_public_key_unref(&payment_public_key);
        cardano_bip32_public_key_unref(&stake_public_key);
        cardano_ed25519_public_key_unref(&payment_key);
        return nullptr;
    }

    cardano_base_address_t* base_address = nullptr;
    cardano_credential_t* payment_cred = create_credential(payment_key);
    cardano_credential_t* stake_cred = create_credential(stake_key);

    result = cardano_base_address_from_credentials(CARDANO_NETWORK_ID_MAIN_NET, payment_cred, stake_cred, &base_address);

    // Cleanup
    cardano_bip32_public_key_unref(&root_public_key);
    cardano_bip32_public_key_unref(&payment_public_key);
    cardano_bip32_public_key_unref(&stake_public_key);
    cardano_credential_unref(&payment_cred);
    cardano_credential_unref(&stake_cred);
    cardano_ed25519_public_key_unref(&payment_key);
    cardano_ed25519_public_key_unref(&stake_key);

    if (result != CARDANO_SUCCESS) {
        return nullptr;
    }

    cardano_address_t* address = cardano_base_address_to_address(base_address);
    cardano_base_address_unref(&base_address);
    return address;
}

void UCardanoBlueprintLibrary::GenerateWallet(TArray<FString>& OutMnemonicWords, FString& OutAddress, const FString& Password)
{
    UE_LOG(LogTemp, Warning, TEXT("Starting wallet generation..."));

    if (sodium_init() < 0) {
        UE_LOG(LogTemp, Error, TEXT("Libsodium initialization failed"));
        return;
    }
    UE_LOG(LogTemp, Warning, TEXT("Libsodium initialized successfully"));

    byte_t entropy[32];
    randombytes_buf(entropy, sizeof(entropy));
    UE_LOG(LogTemp, Warning, TEXT("Generated %d bytes of entropy"), sizeof(entropy));

    const char* word_array[24] = { nullptr };
    size_t word_count = 0;

    cardano_error_t result = cardano_bip39_entropy_to_mnemonic_words(
        entropy,
        sizeof(entropy),
        word_array,
        &word_count
    );

    if (result != CARDANO_SUCCESS || word_count == 0) {
        UE_LOG(LogTemp, Error, TEXT("Mnemonic generation failed: %s"), UTF8_TO_TCHAR(cardano_error_to_string(result)));
        return;
    }
    UE_LOG(LogTemp, Warning, TEXT("Generated %d mnemonic words"), word_count);

    OutMnemonicWords.Empty();
    for (size_t i = 0; i < word_count; i++) {
        FString Word = UTF8_TO_TCHAR(word_array[i]);
        OutMnemonicWords.Add(Word);
        UE_LOG(LogTemp, Warning, TEXT("Word %d: %s"), i + 1, *Word);
    }

    const TCHAR* PassphraseStr = TEXT("password");
    const char* PassphraseUtf8 = TCHAR_TO_UTF8(PassphraseStr);
    UE_LOG(LogTemp, Warning, TEXT("Using passphrase: %s"), PassphraseStr);

    cardano_secure_key_handler_t* key_handler = nullptr;
    result = cardano_software_secure_key_handler_new(
        entropy,
        sizeof(entropy),
        (const byte_t*)PassphraseUtf8,
        strlen(PassphraseUtf8),
        &GetPassphrase,
        &key_handler
    );

    if (result != CARDANO_SUCCESS || !key_handler) {
        UE_LOG(LogTemp, Error, TEXT("Key handler creation failed: %s"), UTF8_TO_TCHAR(cardano_error_to_string(result)));
        return;
    }
    UE_LOG(LogTemp, Warning, TEXT("Key handler created successfully"));

    cardano_address_t* address = create_address_from_derivation_paths(
        key_handler,
        ACCOUNT_DERIVATION_PATH,
        0,
        0
    );

    if (address) {
        OutAddress = UTF8_TO_TCHAR(cardano_address_get_string(address));
        UE_LOG(LogTemp, Warning, TEXT("Generated address: %s"), *OutAddress);
        cardano_address_unref(&address);
    }
    else {
        UE_LOG(LogTemp, Error, TEXT("Address generation failed"));
    }

    cardano_secure_key_handler_unref(&key_handler);
    UE_LOG(LogTemp, Warning, TEXT("Wallet generation completed"));
}

int32 UCardanoBlueprintLibrary::GetPassphrase(byte_t* buffer, size_t buffer_len)
{
    const TCHAR* PassphraseStr = TEXT("password");
    const char* PassphraseUtf8 = TCHAR_TO_UTF8(PassphraseStr);
    const int32 PassphraseLen = strlen(PassphraseUtf8);

    if (buffer_len < PassphraseLen)
    {
        return -1;
    }

    FMemory::Memcpy(buffer, PassphraseUtf8, PassphraseLen);
    return PassphraseLen;
}

void UCardanoBlueprintLibrary::RestoreWallet(const TArray<FString>& MnemonicWords, FString& OutAddress, const FString& Password)
{
    UE_LOG(LogTemp, Warning, TEXT("Starting wallet restoration..."));

    if (sodium_init() < 0) {
        UE_LOG(LogTemp, Error, TEXT("Libsodium initialization failed"));
        return;
    }

    // Validate mnemonic word count
    if (MnemonicWords.Num() != 24) {
        UE_LOG(LogTemp, Error, TEXT("Invalid mnemonic word count. Expected 24, got %d"), MnemonicWords.Num());
        return;
    }

    // Convert and sanitize mnemonic words to C-style array
    const char* word_array[24] = { nullptr };
    for (int32 i = 0; i < MnemonicWords.Num(); i++) {
        // Trim whitespace and convert to lowercase
        FString SanitizedWord = MnemonicWords[i].TrimStartAndEnd().ToLower();

        // Remove any non-ascii characters
        FString CleanWord;
        for (TCHAR Character : SanitizedWord) {
            if (Character >= 32 && Character <= 126) {
                CleanWord.AppendChar(Character);
            }
        }

        // Allocate memory for the C string that will persist through function
        char* word = (char*)malloc(CleanWord.Len() + 1);
        if (!word) {
            // Clean up previously allocated strings
            for (int32 j = 0; j < i; j++) {
                free((void*)word_array[j]);
            }
            UE_LOG(LogTemp, Error, TEXT("Memory allocation failed"));
            return;
        }

        FCStringAnsi::Strcpy(word, CleanWord.Len() + 1, TCHAR_TO_UTF8(*CleanWord));
        word_array[i] = word;

        //UE_LOG(LogTemp, Warning, TEXT("Sanitized word %d: %s"), i + 1, *CleanWord);
    }

    // Convert mnemonic to entropy
    byte_t entropy[64] = { 0 };
    size_t entropy_size = 0;

    cardano_error_t result = cardano_bip39_mnemonic_words_to_entropy(
        word_array,
        24,  // Explicitly specify 24 words
        entropy,
        sizeof(entropy),
        &entropy_size
    );

    // Free allocated word strings
    for (int32 i = 0; i < 24; i++) {
        free((void*)word_array[i]);
    }

    if (result != CARDANO_SUCCESS) {
        UE_LOG(LogTemp, Error, TEXT("Failed to convert mnemonic to entropy: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        return;
    }

    // Create key handler with provided password
    FString SanitizedPassword = Password.TrimStartAndEnd();
    const char* PassphraseUtf8 = TCHAR_TO_UTF8(*SanitizedPassword);
    cardano_secure_key_handler_t* key_handler = nullptr;

    result = cardano_software_secure_key_handler_new(
        entropy,
        entropy_size,
        (const byte_t*)PassphraseUtf8,
        strlen(PassphraseUtf8),
        &GetPassphrase,
        &key_handler
    );

    if (result != CARDANO_SUCCESS || !key_handler) {
        UE_LOG(LogTemp, Error, TEXT("Key handler creation failed: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        return;
    }

    // Generate address using the same derivation path as wallet creation
    cardano_address_t* address = create_address_from_derivation_paths(
        key_handler,
        ACCOUNT_DERIVATION_PATH,
        0,  // payment index
        0   // stake key index
    );

    if (address) {
        OutAddress = UTF8_TO_TCHAR(cardano_address_get_string(address));
        UE_LOG(LogTemp, Warning, TEXT("Restored address: %s"), *OutAddress);
        cardano_address_unref(&address);
    }
    else {
        UE_LOG(LogTemp, Error, TEXT("Address restoration failed"));
    }

    cardano_secure_key_handler_unref(&key_handler);
    UE_LOG(LogTemp, Warning, TEXT("Wallet restoration completed"));
}

void UCardanoBlueprintLibrary::QueryBalanceWithKoios(const FString& Address, FAddressBalance& OutBalance, const FOnBalanceResult& OnComplete)
{
    FString Url = TEXT("https://api.koios.rest/api/v1/address_info");

    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create request body
    TSharedPtr<FJsonObject> RequestObj = MakeShared<FJsonObject>();
    TArray<TSharedPtr<FJsonValue>> AddressArray;
    AddressArray.Add(MakeShared<FJsonValueString>(Address));
    RequestObj->SetArrayField("_addresses", AddressArray);

    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(RequestObj.ToSharedRef(), Writer);

    HttpRequest->SetContentAsString(RequestBody);
    HttpRequest->SetURL(Url);

    HttpRequest->OnProcessRequestComplete().BindLambda([OnComplete, &OutBalance](FHttpRequestPtr Request, FHttpResponsePtr Response, bool Success)
        {
            if (!Success || !Response.IsValid())
            {
                OnComplete.ExecuteIfBound(false, TEXT("Network request failed"));
                return;
            }

            const FString ResponseString = Response->GetContentAsString();
            TArray<TSharedPtr<FJsonValue>> JsonArray;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(ResponseString);

            if (!FJsonSerializer::Deserialize(Reader, JsonArray) || JsonArray.Num() == 0)
            {
                OnComplete.ExecuteIfBound(false, TEXT("Invalid response format"));
                return;
            }

            TSharedPtr<FJsonObject> AddressInfo = JsonArray[0]->AsObject();
            if (!AddressInfo.IsValid())
            {
                OnComplete.ExecuteIfBound(false, TEXT("Invalid address info"));
                return;
            }

            FString BalanceStr;
            if (AddressInfo->TryGetStringField("balance", BalanceStr))
            {
                OutBalance.Lovelace = FCString::Atoi64(*BalanceStr);
            }

            const TArray<TSharedPtr<FJsonValue>>* UtxoSet = nullptr;
            if (AddressInfo->TryGetArrayField("utxo_set", UtxoSet) && UtxoSet)
            {
                for (const auto& UtxoValue : *UtxoSet)
                {
                    auto UtxoObject = UtxoValue->AsObject();
                    if (!UtxoObject.IsValid()) continue;

                    const TArray<TSharedPtr<FJsonValue>>* AssetList = nullptr;
                    if (UtxoObject->TryGetArrayField("asset_list", AssetList) && AssetList)
                    {
                        for (const auto& AssetValue : *AssetList)
                        {
                            auto AssetObject = AssetValue->AsObject();
                            if (!AssetObject.IsValid()) continue;

                            FTokenBalance TokenBalance;
                            AssetObject->TryGetStringField("policy_id", TokenBalance.PolicyId);
                            AssetObject->TryGetStringField("asset_name", TokenBalance.AssetName);
                            AssetObject->TryGetStringField("quantity", TokenBalance.Quantity);
                            OutBalance.Tokens.Add(TokenBalance);
                        }
                    }
                }
            }

            OnComplete.ExecuteIfBound(true, TEXT(""));
        });

    HttpRequest->ProcessRequest();
}

void UCardanoBlueprintLibrary::SubmitTransactionWithKoios(const TArray<uint8>& TransactionBytes, const FString& KoiosApiEndpoint)
{
    if (TransactionBytes.Num() == 0)
    {
        UE_LOG(LogTemp, Error, TEXT("Invalid transaction bytes: Empty array"));
        return;
    }

    // Validate and format API endpoint
    FString EndpointToUse = KoiosApiEndpoint;
    if (EndpointToUse.IsEmpty())
    {
        EndpointToUse = TEXT("https://api.koios.rest/api/v1");
    }

    // Ensure base endpoint doesn't end with a slash
    if (EndpointToUse.EndsWith(TEXT("/")))
    {
        EndpointToUse.RemoveAt(EndpointToUse.Len() - 1);
    }

    // Add the correct submit transaction endpoint
    FString SubmitEndpoint = FString::Printf(TEXT("%s/submittx"), *EndpointToUse);

    UE_LOG(LogTemp, Log, TEXT("Submitting transaction to endpoint: %s"), *SubmitEndpoint);
    UE_LOG(LogTemp, Log, TEXT("Transaction size: %d bytes"), TransactionBytes.Num());

    // Create HTTP request
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/cbor"));

    // Set the binary content
    HttpRequest->SetContent(TransactionBytes);
    HttpRequest->SetURL(SubmitEndpoint);

    // Add request timeout
    HttpRequest->SetTimeout(30.0f);

    HttpRequest->OnProcessRequestComplete().BindLambda(
        [](FHttpRequestPtr Request, FHttpResponsePtr Response, bool Success)
        {
            if (!Success)
            {
                UE_LOG(LogTemp, Error, TEXT("Transaction submission failed: Network error"));
                return;
            }

            if (!Response.IsValid())
            {
                UE_LOG(LogTemp, Error, TEXT("Transaction submission failed: Invalid response"));
                return;
            }

            const int32 ResponseCode = Response->GetResponseCode();
            const FString ResponseString = Response->GetContentAsString();

            if (ResponseCode == 202)
            {
                UE_LOG(LogTemp, Log, TEXT("Transaction submitted successfully"));
                UE_LOG(LogTemp, Log, TEXT("Response: %s"), *ResponseString);
            }
            else
            {
                UE_LOG(LogTemp, Error, TEXT("Transaction submission failed with code: %d"), ResponseCode);
                UE_LOG(LogTemp, Error, TEXT("Error response: %s"), *ResponseString);

                // Additional debug information
                UE_LOG(LogTemp, Log, TEXT("Request URL: %s"), *Request->GetURL());
                UE_LOG(LogTemp, Log, TEXT("Request headers:"));
                const TArray<FString>& Headers = Request->GetAllHeaders();
                for (const FString& Header : Headers)
                {
                    UE_LOG(LogTemp, Log, TEXT("  %s"), *Header);
                }
            }
        });

    HttpRequest->ProcessRequest();
}

void UCardanoBlueprintLibrary::QueryBalanceWithOgmios(
    const FString& OgmiosURL,
    const FString& Address,
    const FOnBalanceQueryComplete& OnComplete)
{
    // Input validation
    if (OgmiosURL.IsEmpty() || Address.IsEmpty())
    {
        FOgmiosBalanceResponse Response;
        Response.bSuccess = false;
        Response.ErrorMessage = TEXT("Invalid input parameters");
        OnComplete.ExecuteIfBound(Response);
        return;
    }

    // Create HTTP request
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetURL(OgmiosURL);
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create JSON-RPC payload
    TSharedPtr<FJsonObject> JsonObject = MakeShared<FJsonObject>();
    JsonObject->SetStringField(TEXT("jsonrpc"), TEXT("2.0"));
    JsonObject->SetStringField(TEXT("method"), TEXT("queryLedgerState/utxo"));

    // Create params object
    TSharedPtr<FJsonObject> ParamsObject = MakeShared<FJsonObject>();
    TArray<TSharedPtr<FJsonValue>> AddressArray;
    AddressArray.Add(MakeShared<FJsonValueString>(Address));
    ParamsObject->SetArrayField(TEXT("addresses"), AddressArray);

    JsonObject->SetObjectField(TEXT("params"), ParamsObject);
    JsonObject->SetNumberField(TEXT("id"), 1);

    // Serialize JSON
    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(JsonObject.ToSharedRef(), Writer);

    HttpRequest->SetContentAsString(JsonString);

    // Set up response handler
    HttpRequest->OnProcessRequestComplete().BindLambda(
        [OnComplete](FHttpRequestPtr Request, FHttpResponsePtr Response, bool bConnected)
        {
            FOgmiosBalanceResponse BalanceResponse;
            BalanceResponse.bSuccess = false;

            if (!bConnected || !Response.IsValid())
            {
                BalanceResponse.ErrorMessage = TEXT("Failed to connect to Ogmios server");
                OnComplete.ExecuteIfBound(BalanceResponse);
                return;
            }

            // Parse response
            TSharedPtr<FJsonObject> JsonResponse;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response->GetContentAsString());

            if (!FJsonSerializer::Deserialize(Reader, JsonResponse))
            {
                BalanceResponse.ErrorMessage = TEXT("Failed to parse server response");
                OnComplete.ExecuteIfBound(BalanceResponse);
                return;
            }

            // Check for errors
            if (JsonResponse->HasField(TEXT("error")))
            {
                const TSharedPtr<FJsonObject>* ErrorObj;
                if (JsonResponse->TryGetObjectField(TEXT("error"), ErrorObj))
                {
                    FString ErrorMessage;
                    (*ErrorObj)->TryGetStringField(TEXT("message"), ErrorMessage);
                    BalanceResponse.ErrorMessage = ErrorMessage;
                    OnComplete.ExecuteIfBound(BalanceResponse);
                    return;
                }
            }

            // Process UTxO results
            const TArray<TSharedPtr<FJsonValue>>* ResultArray;
            if (JsonResponse->TryGetArrayField(TEXT("result"), ResultArray))
            {
                int64 TotalLovelace = 0;
                TMap<FString, int64> TokenBalances;

                // Sum up all UTxOs
                for (const auto& UtxoValue : *ResultArray)
                {
                    const TSharedPtr<FJsonObject> UtxoObj = UtxoValue->AsObject();
                    if (!UtxoObj.IsValid()) continue;

                    const TSharedPtr<FJsonObject>* ValueObj;
                    if (UtxoObj->TryGetObjectField(TEXT("value"), ValueObj))
                    {
                        // Process ADA (lovelace)
                        int64 Lovelace = 0;
                        if ((*ValueObj)->TryGetNumberField(TEXT("lovelace"), Lovelace))
                        {
                            TotalLovelace += Lovelace;
                        }

                        // Process other tokens
                        for (const auto& TokenPair : (*ValueObj)->Values)
                        {
                            if (TokenPair.Key != TEXT("lovelace"))
                            {
                                const TSharedPtr<FJsonObject> AssetObj = TokenPair.Value->AsObject();
                                if (!AssetObj.IsValid()) continue;

                                for (const auto& AssetPair : AssetObj->Values)
                                {
                                    FString AssetKey = FString::Printf(TEXT("%s.%s"), *TokenPair.Key, *AssetPair.Key);
                                    int64 Amount = 0;
                                    if (AssetPair.Value->TryGetNumber(Amount))
                                    {
                                        TokenBalances.FindOrAdd(AssetKey) += Amount;
                                    }
                                }
                            }
                        }
                    }
                }

                // Fill response
                BalanceResponse.bSuccess = true;
                BalanceResponse.Balance.Lovelace = TotalLovelace;

                // Convert token balances to response format
                for (const auto& TokenPair : TokenBalances)
                {
                    FTokenBalance TokenBalance;
                    TArray<FString> Parts;
                    TokenPair.Key.ParseIntoArray(Parts, TEXT("."), true);
                    if (Parts.Num() >= 2)
                    {
                        TokenBalance.PolicyId = Parts[0];
                        TokenBalance.AssetName = Parts[1];
                        TokenBalance.Quantity = FString::Printf(TEXT("%lld"), TokenPair.Value);
                        TokenBalance.DisplayName = DecodeCardanoAssetName(Parts[1]);
                        BalanceResponse.Balance.Tokens.Add(TokenBalance);
                    }
                }
            }

            OnComplete.ExecuteIfBound(BalanceResponse);
        });

    // Send request
    HttpRequest->ProcessRequest();
}

void UCardanoBlueprintLibrary::RegisterWithWalletServer(
    const FString& WalletURL,
    const FString& Passphrase,
    const TArray<FString>& MnemonicWords,
    const FOnWalletRegistrationComplete& OnComplete,
    EWalletRestorationMode RestorationMode)
{
    FWalletRegistrationResponse Response;
    Response.bSuccess = false;

    // Validate input
    if (Passphrase.IsEmpty() || Passphrase.Len() < 10)
    {
        Response.ErrorMessage = TEXT("Passphrase must be at least 10 characters long");
        OnComplete.ExecuteIfBound(Response);
        return;
    }

    if (WalletURL.IsEmpty())
    {
        Response.ErrorMessage = TEXT("Must have URL for Wallet API");
        OnComplete.ExecuteIfBound(Response);
        return;
    }

    if (MnemonicWords.Num() != 24)
    {
        Response.ErrorMessage = TEXT("Invalid mnemonic word count");
        OnComplete.ExecuteIfBound(Response);
        return;
    }

    // Log attempt
    UE_LOG(LogTemp, Log, TEXT("Attempting wallet registration at URL: %s"), *WalletURL);

    // Create the request
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetURL(WalletURL + TEXT("/v2/wallets"));
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create JSON payload
    TSharedPtr<FJsonObject> JsonObject = MakeShared<FJsonObject>();
    JsonObject->SetStringField(TEXT("name"), TEXT("Unreal Engine Wallet"));
    JsonObject->SetNumberField(TEXT("address_pool_gap"), 20);

    // Add mnemonic words array
    TArray<TSharedPtr<FJsonValue>> MnemonicArray;
    for (const FString& Word : MnemonicWords)
    {
        MnemonicArray.Add(MakeShared<FJsonValueString>(Word));
    }
    JsonObject->SetArrayField(TEXT("mnemonic_sentence"), MnemonicArray);
    JsonObject->SetStringField(TEXT("passphrase"), Passphrase);

    // Add restoration mode
    switch (RestorationMode)
    {
    case EWalletRestorationMode::FROM_GENESIS:
        JsonObject->SetStringField(TEXT("restoration_mode"), TEXT("from_genesis"));
        break;
    case EWalletRestorationMode::FROM_TIP:
        JsonObject->SetStringField(TEXT("restoration_mode"), TEXT("from_tip"));
        break;
    case EWalletRestorationMode::FROM_BLOCK:
        Response.ErrorMessage = TEXT("FROM_BLOCK restoration requires additional block details");
        OnComplete.ExecuteIfBound(Response);
        return;
    }

    // Serialize JSON
    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(JsonObject.ToSharedRef(), Writer);

    // Log sanitized version of request (excluding sensitive data)
    if (UE_LOG_ACTIVE(LogTemp, Verbose))
    {
        TSharedPtr<FJsonObject> LogJsonObject = MakeShared<FJsonObject>();
        LogJsonObject->SetStringField(TEXT("name"), TEXT("Unreal Engine Wallet"));
        LogJsonObject->SetNumberField(TEXT("address_pool_gap"), 20);
        LogJsonObject->SetStringField(TEXT("passphrase"), TEXT("***REDACTED***"));
        LogJsonObject->SetStringField(TEXT("restoration_mode"),
            RestorationMode == EWalletRestorationMode::FROM_GENESIS ? TEXT("from_genesis") : TEXT("from_tip"));

        TArray<TSharedPtr<FJsonValue>> LogMnemonicArray;
        for (int32 i = 0; i < MnemonicWords.Num(); ++i)
        {
            LogMnemonicArray.Add(MakeShared<FJsonValueString>(TEXT("***REDACTED***")));
        }
        LogJsonObject->SetArrayField(TEXT("mnemonic_sentence"), LogMnemonicArray);

        FString LogJsonString;
        TSharedRef<TJsonWriter<>> LogWriter = TJsonWriterFactory<>::Create(&LogJsonString);
        FJsonSerializer::Serialize(LogJsonObject.ToSharedRef(), LogWriter);
        UE_LOG(LogTemp, Verbose, TEXT("Request Payload (sanitized): %s"), *LogJsonString);
    }

    HttpRequest->SetContentAsString(JsonString);

    // Set up response handler
    HttpRequest->OnProcessRequestComplete().BindLambda(
        [OnComplete](FHttpRequestPtr Request, FHttpResponsePtr Response, bool bConnected)
        {
            FWalletRegistrationResponse RegResponse;
            RegResponse.bSuccess = false;

            if (!bConnected)
            {
                RegResponse.ErrorMessage = TEXT("Connection failed - check network connectivity");
                OnComplete.ExecuteIfBound(RegResponse);
                return;
            }

            if (!Response.IsValid())
            {
                RegResponse.ErrorMessage = TEXT("Invalid response received");
                OnComplete.ExecuteIfBound(RegResponse);
                return;
            }

            // Log response code
            UE_LOG(LogTemp, Log, TEXT("Response Code: %d"), Response->GetResponseCode());

            // Get response content
            FString ResponseContent = Response->GetContentAsString();
            UE_LOG(LogTemp, Log, TEXT("Response Content: %s"), *ResponseContent);

            if (Response->GetResponseCode() != 201)
            {
                // Parse error response
                TSharedPtr<FJsonObject> JsonResponse;
                TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(ResponseContent);

                if (FJsonSerializer::Deserialize(Reader, JsonResponse))
                {
                    FString Message;
                    FString Code;
                    JsonResponse->TryGetStringField(TEXT("message"), Message);
                    JsonResponse->TryGetStringField(TEXT("code"), Code);
                    RegResponse.ErrorMessage = FString::Printf(TEXT("Failed with code %s: %s"), *Code, *Message);
                }
                else
                {
                    RegResponse.ErrorMessage = FString::Printf(TEXT("Failed with status code %d"), Response->GetResponseCode());
                }

                OnComplete.ExecuteIfBound(RegResponse);
                return;
            }

            // Parse success response
            TSharedPtr<FJsonObject> JsonResponse;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(ResponseContent);

            if (FJsonSerializer::Deserialize(Reader, JsonResponse))
            {
                // Get wallet ID
                JsonResponse->TryGetStringField(TEXT("id"), RegResponse.WalletId);

                // Parse balance if available
                const TSharedPtr<FJsonObject>* BalanceObj;
                if (JsonResponse->TryGetObjectField(TEXT("balance"), BalanceObj))
                {
                    // Parse ADA balance
                    const TSharedPtr<FJsonObject>* AvailableObj;
                    if ((*BalanceObj)->TryGetObjectField(TEXT("available"), AvailableObj))
                    {
                        int64 Quantity = 0;
                        if ((*AvailableObj)->TryGetNumberField(TEXT("quantity"), Quantity))
                        {
                            RegResponse.Balance.Lovelace = Quantity;
                        }
                    }

                    // Parse tokens if any
                    const TArray<TSharedPtr<FJsonValue>>* AssetsArray;
                    if ((*BalanceObj)->TryGetArrayField(TEXT("assets"), AssetsArray))
                    {
                        for (const auto& AssetValue : *AssetsArray)
                        {
                            const TSharedPtr<FJsonObject> AssetObj = AssetValue->AsObject();
                            if (!AssetObj.IsValid()) continue;

                            FTokenBalance Token;
                            AssetObj->TryGetStringField(TEXT("policy_id"), Token.PolicyId);
                            AssetObj->TryGetStringField(TEXT("asset_name"), Token.AssetName);

                            FString QuantityStr;
                            if (AssetObj->TryGetStringField(TEXT("quantity"), QuantityStr))
                            {
                                Token.Quantity = QuantityStr;
                                RegResponse.Balance.Tokens.Add(Token);
                            }
                        }
                    }
                }

                RegResponse.bSuccess = true;
            }
            else
            {
                RegResponse.ErrorMessage = TEXT("Failed to parse successful response");
            }

            OnComplete.ExecuteIfBound(RegResponse);
        });

    // Send request
    HttpRequest->ProcessRequest();
}

bool UCardanoBlueprintLibrary::SendADAWithWalletServer(
    const FString& ReceiverAddress,
    const FString& WalletURL,
    int64 AmountLovelace,
    int64 FeeLovelace,
    const FString& Password,
    FTokenTransactionResult& OutResult)
{
    // Input validation
    if (WalletURL.IsEmpty() || ReceiverAddress.IsEmpty() || AmountLovelace <= 0 || Password.IsEmpty())
    {
        OutResult.bSuccess = false;
        OutResult.ErrorMessage = TEXT("Invalid input parameters");
        return false;
    }

    // Two-step process: Construct then Submit
    FString ConstructedTransaction;
    bool bConstructionComplete = false;

    // Step 1: Construct Transaction
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> ConstructRequest = FHttpModule::Get().CreateRequest();
    ConstructRequest->SetVerb("POST");
    ConstructRequest->SetURL(WalletURL + TEXT("/v2/wallets/transactions-construct"));
    ConstructRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create JSON payload
    TSharedPtr<FJsonObject> JsonObject = MakeShared<FJsonObject>();

    // Add payment
    TArray<TSharedPtr<FJsonValue>> PaymentsArray;
    TSharedPtr<FJsonObject> PaymentObj = MakeShared<FJsonObject>();
    PaymentObj->SetStringField(TEXT("address"), ReceiverAddress);
    PaymentObj->SetNumberField(TEXT("amount"), AmountLovelace);
    PaymentsArray.Add(MakeShared<FJsonValueObject>(PaymentObj));
    JsonObject->SetArrayField(TEXT("payments"), PaymentsArray);

    // Add passphrase for signing
    JsonObject->SetStringField(TEXT("passphrase"), Password);

    // Optional: Set fee if specified
    if (FeeLovelace > 0)
    {
        JsonObject->SetNumberField(TEXT("fee"), FeeLovelace);
    }

    // Serialize JSON
    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(JsonObject.ToSharedRef(), Writer);
    ConstructRequest->SetContentAsString(JsonString);

    ConstructRequest->OnProcessRequestComplete().BindLambda(
        [&bConstructionComplete, &ConstructedTransaction, &OutResult](FHttpRequestPtr Request, FHttpResponsePtr HttpResponse, bool bConnected)
        {
            if (bConnected && HttpResponse.IsValid() && HttpResponse->GetResponseCode() == 202)
            {
                ConstructedTransaction = HttpResponse->GetContentAsString();
                bConstructionComplete = true;
            }
            else
            {
                OutResult.bSuccess = false;
                OutResult.ErrorMessage = TEXT("Transaction construction failed");
                bConstructionComplete = true;
            }
        });

    ConstructRequest->ProcessRequest();

    // Wait for construction with timeout
    const float TimeoutSeconds = 30.0f;
    const float StartTime = FPlatformTime::Seconds();
    while (!bConstructionComplete)
    {
        if (FPlatformTime::Seconds() - StartTime > TimeoutSeconds)
        {
            OutResult.bSuccess = false;
            OutResult.ErrorMessage = TEXT("Transaction construction timed out");
            return false;
        }
        FPlatformProcess::Sleep(0.1f);
    }

    // Step 2: Submit Transaction
    if (ConstructedTransaction.IsEmpty())
    {
        OutResult.bSuccess = false;
        OutResult.ErrorMessage = TEXT("No transaction to submit");
        return false;
    }

    bool bSubmissionComplete = false;
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> SubmitRequest = FHttpModule::Get().CreateRequest();
    SubmitRequest->SetVerb("POST");
    SubmitRequest->SetURL(WalletURL + TEXT("/v2/wallets/transactions-submit"));
    SubmitRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    SubmitRequest->SetContentAsString(ConstructedTransaction);

    SubmitRequest->OnProcessRequestComplete().BindLambda(
        [&bSubmissionComplete, &OutResult](FHttpRequestPtr Request, FHttpResponsePtr HttpResponse, bool bConnected)
        {
            if (bConnected && HttpResponse.IsValid() && HttpResponse->GetResponseCode() == 202)
            {
                TSharedPtr<FJsonObject> JsonResponse;
                TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(HttpResponse->GetContentAsString());
                if (FJsonSerializer::Deserialize(Reader, JsonResponse) && JsonResponse->HasField(TEXT("id")))
                {
                    OutResult.bSuccess = true;
                    OutResult.TransactionId = JsonResponse->GetStringField(TEXT("id"));
                }
                else
                {
                    OutResult.bSuccess = false;
                    OutResult.ErrorMessage = TEXT("Invalid transaction submission response");
                }
            }
            else
            {
                OutResult.bSuccess = false;
                OutResult.ErrorMessage = TEXT("Transaction submission failed");
            }
            bSubmissionComplete = true;
        });

    SubmitRequest->ProcessRequest();

    // Wait for submission with timeout
    while (!bSubmissionComplete)
    {
        if (FPlatformTime::Seconds() - StartTime > TimeoutSeconds)
        {
            OutResult.bSuccess = false;
            OutResult.ErrorMessage = TEXT("Transaction submission timed out");
            return false;
        }
        FPlatformProcess::Sleep(0.1f);
    }

    return OutResult.bSuccess;
}

bool UCardanoBlueprintLibrary::SendTokensWithWalletServer(
    const FString& WalletURL,
    const FString& ReceiverAddress,
    const TArray<FTokenTransfer>& Transfers,
    const FString& Passphrase,
    FTokenTransactionResult& OutResult) 
{
    // Input validation
    if (WalletURL.IsEmpty() || ReceiverAddress.IsEmpty() || Transfers.Num() == 0 || Passphrase.IsEmpty())
    {
        OutResult.bSuccess = false;
        OutResult.ErrorMessage = TEXT("Invalid input parameters");
        return false;
    }

    // Two-step process: Construct then Submit
    FString ConstructedTransaction;
    bool bConstructionComplete = false;

    // Step 1: Construct Transaction
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> ConstructRequest = FHttpModule::Get().CreateRequest();
    ConstructRequest->SetVerb("POST");
    ConstructRequest->SetURL(WalletURL + TEXT("/v2/wallets/transactions-construct"));
    ConstructRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create JSON payload
    TSharedPtr<FJsonObject> JsonObject = MakeShared<FJsonObject>();

    // Add payments
    TArray<TSharedPtr<FJsonValue>> PaymentsArray;
    for (const FTokenTransfer& Transfer : Transfers)
    {
        TSharedPtr<FJsonObject> PaymentObj = MakeShared<FJsonObject>();
        PaymentObj->SetStringField(TEXT("address"), ReceiverAddress);

        // For ADA transfer
        if (Transfer.PolicyId.IsEmpty())
        {
            PaymentObj->SetNumberField(TEXT("amount"), Transfer.Amount);
        }
        else
        {
            // For token transfer
            TSharedPtr<FJsonObject> AssetsObj = MakeShared<FJsonObject>();
            AssetsObj->SetStringField(Transfer.PolicyId, FString::FromInt(Transfer.Amount));
            PaymentObj->SetObjectField(TEXT("assets"), AssetsObj);
        }

        PaymentsArray.Add(MakeShared<FJsonValueObject>(PaymentObj));
    }
    JsonObject->SetArrayField(TEXT("payments"), PaymentsArray);

    // Add passphrase for signing
    JsonObject->SetStringField(TEXT("passphrase"), Passphrase);

    // Serialize JSON
    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(JsonObject.ToSharedRef(), Writer);
    ConstructRequest->SetContentAsString(JsonString);

    ConstructRequest->OnProcessRequestComplete().BindLambda(
        [&bConstructionComplete, &ConstructedTransaction, &OutResult](FHttpRequestPtr Request, FHttpResponsePtr HttpResponse, bool bConnected)
        {
            if (bConnected && HttpResponse.IsValid() && HttpResponse->GetResponseCode() == 202)
            {
                ConstructedTransaction = HttpResponse->GetContentAsString();
                bConstructionComplete = true;
            }
            else
            {
                OutResult.bSuccess = false;
                OutResult.ErrorMessage = TEXT("Transaction construction failed");
                bConstructionComplete = true;
            }
        });

    ConstructRequest->ProcessRequest();

    // Wait for construction with timeout
    const float TimeoutSeconds = 30.0f;
    const float StartTime = FPlatformTime::Seconds();
    while (!bConstructionComplete)
    {
        if (FPlatformTime::Seconds() - StartTime > TimeoutSeconds)
        {
            OutResult.bSuccess = false;
            OutResult.ErrorMessage = TEXT("Transaction construction timed out");
            return false;
        }
        FPlatformProcess::Sleep(0.1f);
    }

    // Step 2: Submit Transaction
    if (ConstructedTransaction.IsEmpty())
    {
        OutResult.bSuccess = false;
        OutResult.ErrorMessage = TEXT("No transaction to submit");
        return false;
    }

    bool bSubmissionComplete = false;
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> SubmitRequest = FHttpModule::Get().CreateRequest();
    SubmitRequest->SetVerb("POST");
    SubmitRequest->SetURL(WalletURL + TEXT("/v2/wallets/transactions-submit"));
    SubmitRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    SubmitRequest->SetContentAsString(ConstructedTransaction);

    SubmitRequest->OnProcessRequestComplete().BindLambda(
        [&bSubmissionComplete, &OutResult](FHttpRequestPtr Request, FHttpResponsePtr HttpResponse, bool bConnected)
        {
            if (bConnected && HttpResponse.IsValid() && HttpResponse->GetResponseCode() == 202)
            {
                TSharedPtr<FJsonObject> JsonResponse;
                TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(HttpResponse->GetContentAsString());
                if (FJsonSerializer::Deserialize(Reader, JsonResponse) && JsonResponse->HasField(TEXT("id")))
                {
                    OutResult.bSuccess = true;
                    OutResult.TransactionId = JsonResponse->GetStringField(TEXT("id"));
                }
                else
                {
                    OutResult.bSuccess = false;
                    OutResult.ErrorMessage = TEXT("Invalid transaction submission response");
                }
            }
            else
            {
                OutResult.bSuccess = false;
                OutResult.ErrorMessage = TEXT("Transaction submission failed");
            }
            bSubmissionComplete = true;
        });

    SubmitRequest->ProcessRequest();

    // Wait for submission with timeout
    while (!bSubmissionComplete)
    {
        if (FPlatformTime::Seconds() - StartTime > TimeoutSeconds)
        {
            OutResult.bSuccess = false;
            OutResult.ErrorMessage = TEXT("Transaction submission timed out");
            return false;
        }
        FPlatformProcess::Sleep(0.1f);
    }

    return OutResult.bSuccess;
}

bool UCardanoBlueprintLibrary::SendTokensAndADAWithWalletServer(
    const FString& WalletURL,
    const FString& ReceiverAddress,
    int64 AmountLovelace,
    int64 FeeLovelace,
    const TArray<FTokenTransfer>& Transfers,
    const FString& Passphrase,
    FTokenTransactionResult& OutResult)
{
    // Input validation
    if (WalletURL.IsEmpty() || ReceiverAddress.IsEmpty() || AmountLovelace < 0 || Passphrase.IsEmpty())
    {
        OutResult.bSuccess = false;
        OutResult.ErrorMessage = TEXT("Invalid input parameters");
        return false;
    }

    // Track completion states
    bool bConstructionComplete = false;
    FString ConstructedTransaction;

    // Step 1: Construct Transaction
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> ConstructRequest = FHttpModule::Get().CreateRequest();
    ConstructRequest->SetVerb("POST");
    ConstructRequest->SetURL(WalletURL + TEXT("/v2/wallets/transactions-construct"));
    ConstructRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create main JSON payload
    TSharedPtr<FJsonObject> JsonObject = MakeShared<FJsonObject>();

    // Create payment object with ADA and tokens
    TSharedPtr<FJsonObject> PaymentObj = MakeShared<FJsonObject>();
    PaymentObj->SetStringField(TEXT("address"), ReceiverAddress);
    PaymentObj->SetNumberField(TEXT("amount"), AmountLovelace);

    // Add token assets if any
    if (Transfers.Num() > 0)
    {
        TSharedPtr<FJsonObject> AssetsObj = MakeShared<FJsonObject>();
        for (const FTokenTransfer& Transfer : Transfers)
        {
            if (!Transfer.PolicyId.IsEmpty())
            {
                AssetsObj->SetNumberField(Transfer.PolicyId, Transfer.Amount);
            }
        }

        if (AssetsObj->Values.Num() > 0)
        {
            PaymentObj->SetObjectField(TEXT("assets"), AssetsObj);
        }
    }

    // Add payment to array
    TArray<TSharedPtr<FJsonValue>> PaymentsArray;
    PaymentsArray.Add(MakeShared<FJsonValueObject>(PaymentObj));
    JsonObject->SetArrayField(TEXT("payments"), PaymentsArray);

    // Add passphrase
    JsonObject->SetStringField(TEXT("passphrase"), Passphrase);

    // Add optional fee if specified
    if (FeeLovelace > 0)
    {
        JsonObject->SetNumberField(TEXT("fee"), FeeLovelace);
    }

    // Serialize and send the request
    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(JsonObject.ToSharedRef(), Writer);
    ConstructRequest->SetContentAsString(JsonString);

    // Handle construction response
    ConstructRequest->OnProcessRequestComplete().BindLambda(
        [&bConstructionComplete, &ConstructedTransaction, &OutResult](FHttpRequestPtr Request, FHttpResponsePtr HttpResponse, bool bConnected)
        {
            if (bConnected && HttpResponse.IsValid() && HttpResponse->GetResponseCode() == 202)
            {
                ConstructedTransaction = HttpResponse->GetContentAsString();
                bConstructionComplete = true;
            }
            else
            {
                OutResult.bSuccess = false;
                OutResult.ErrorMessage = TEXT("Transaction construction failed");
                if (HttpResponse.IsValid())
                {
                    OutResult.ErrorMessage += FString::Printf(TEXT(" (Code: %d)"), HttpResponse->GetResponseCode());
                }
                bConstructionComplete = true;
            }
        });

    ConstructRequest->ProcessRequest();

    // Wait for construction with timeout
    const float TimeoutSeconds = 30.0f;
    const float StartTime = FPlatformTime::Seconds();
    while (!bConstructionComplete)
    {
        if (FPlatformTime::Seconds() - StartTime > TimeoutSeconds)
        {
            OutResult.bSuccess = false;
            OutResult.ErrorMessage = TEXT("Transaction construction timed out");
            return false;
        }
        FPlatformProcess::Sleep(0.1f);
    }

    // Check if construction succeeded
    if (ConstructedTransaction.IsEmpty())
    {
        OutResult.bSuccess = false;
        OutResult.ErrorMessage = TEXT("No transaction to submit");
        return false;
    }

    // Step 2: Submit Transaction
    bool bSubmissionComplete = false;
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> SubmitRequest = FHttpModule::Get().CreateRequest();
    SubmitRequest->SetVerb("POST");
    SubmitRequest->SetURL(WalletURL + TEXT("/v2/wallets/transactions-submit"));
    SubmitRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    SubmitRequest->SetContentAsString(ConstructedTransaction);

    // Handle submission response
    SubmitRequest->OnProcessRequestComplete().BindLambda(
        [&bSubmissionComplete, &OutResult](FHttpRequestPtr Request, FHttpResponsePtr HttpResponse, bool bConnected)
        {
            if (bConnected && HttpResponse.IsValid() && HttpResponse->GetResponseCode() == 202)
            {
                TSharedPtr<FJsonObject> JsonResponse;
                TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(HttpResponse->GetContentAsString());
                if (FJsonSerializer::Deserialize(Reader, JsonResponse) && JsonResponse->HasField(TEXT("id")))
                {
                    OutResult.bSuccess = true;
                    OutResult.TransactionId = JsonResponse->GetStringField(TEXT("id"));
                }
                else
                {
                    OutResult.bSuccess = false;
                    OutResult.ErrorMessage = TEXT("Invalid transaction submission response");
                }
            }
            else
            {
                OutResult.bSuccess = false;
                OutResult.ErrorMessage = TEXT("Transaction submission failed");
                if (HttpResponse.IsValid())
                {
                    OutResult.ErrorMessage += FString::Printf(TEXT(" (Code: %d)"), HttpResponse->GetResponseCode());
                }
            }
            bSubmissionComplete = true;
        });

    SubmitRequest->ProcessRequest();

    // Wait for submission with timeout
    while (!bSubmissionComplete)
    {
        if (FPlatformTime::Seconds() - StartTime > TimeoutSeconds)
        {
            OutResult.bSuccess = false;
            OutResult.ErrorMessage = TEXT("Transaction submission timed out");
            return false;
        }
        FPlatformProcess::Sleep(0.1f);
    }

    return OutResult.bSuccess;
}

bool UCardanoBlueprintLibrary::GetWalletServerNetInfo(
    const FString& WalletURL,
    const FOnNetworkInfoResult& OnComplete)
{
    if (WalletURL.IsEmpty())
    {
        FCardanoNetworkInfo ErrorInfo;
        ErrorInfo.ErrorMessage = TEXT("Invalid wallet server URL");
        OnComplete.ExecuteIfBound(ErrorInfo);
        return false;
    }

    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("GET");
    HttpRequest->SetURL(WalletURL + TEXT("/v2/network/information"));
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    HttpRequest->OnProcessRequestComplete().BindLambda(
        [OnComplete](FHttpRequestPtr Request, FHttpResponsePtr Response, bool bSuccess)
        {
            FCardanoNetworkInfo NetworkInfo;

            if (!bSuccess || !Response.IsValid())
            {
                NetworkInfo.ErrorMessage = TEXT("Failed to connect to wallet server");
                NetworkInfo.bIsConnected = false;
                OnComplete.ExecuteIfBound(NetworkInfo);
                return;
            }

            if (Response->GetResponseCode() != 200)
            {
                NetworkInfo.ErrorMessage = FString::Printf(TEXT("Server returned error code: %d"), Response->GetResponseCode());
                NetworkInfo.bIsConnected = false;
                OnComplete.ExecuteIfBound(NetworkInfo);
                return;
            }

            // Parse the JSON response
            TSharedPtr<FJsonObject> JsonResponse;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response->GetContentAsString());

            if (!FJsonSerializer::Deserialize(Reader, JsonResponse) || !JsonResponse.IsValid())
            {
                NetworkInfo.ErrorMessage = TEXT("Failed to parse server response");
                NetworkInfo.bIsConnected = false;
                OnComplete.ExecuteIfBound(NetworkInfo);
                return;
            }

            // Parse sync progress
            const TSharedPtr<FJsonObject>* SyncProgressObj;
            if (JsonResponse->TryGetObjectField(TEXT("sync_progress"), SyncProgressObj))
            {
                FString Status;
                if ((*SyncProgressObj)->TryGetStringField(TEXT("status"), Status))
                {
                    NetworkInfo.bIsConnected = true;

                    if (Status == TEXT("ready"))
                    {
                        NetworkInfo.SyncProgress = 100.0f;
                    }
                    else if (Status == TEXT("syncing"))
                    {
                        const TSharedPtr<FJsonObject>* ProgressObj;
                        if ((*SyncProgressObj)->TryGetObjectField(TEXT("progress"), ProgressObj))
                        {
                            double Quantity = 0.0;
                            if ((*ProgressObj)->TryGetNumberField(TEXT("quantity"), Quantity))
                            {
                                NetworkInfo.SyncProgress = static_cast<float>(Quantity);
                            }
                        }
                    }
                }
            }

            // Parse network information
            const TSharedPtr<FJsonObject>* NetworkInfoObj;
            if (JsonResponse->TryGetObjectField(TEXT("network_info"), NetworkInfoObj))
            {
                (*NetworkInfoObj)->TryGetStringField(TEXT("network_id"), NetworkInfo.NetworkId);
            }

            // Parse node tip information
            const TSharedPtr<FJsonObject>* NodeTipObj;
            if (JsonResponse->TryGetObjectField(TEXT("node_tip"), NodeTipObj))
            {
                // Get height
                const TSharedPtr<FJsonObject>* HeightObj;
                if ((*NodeTipObj)->TryGetObjectField(TEXT("height"), HeightObj))
                {
                    int32 Quantity = 0;
                    if ((*HeightObj)->TryGetNumberField(TEXT("quantity"), Quantity))
                    {
                        NetworkInfo.NodeTipHeight = Quantity;
                    }
                }

                // Get slot number
                (*NodeTipObj)->TryGetNumberField(TEXT("slot_number"), NetworkInfo.NodeTipSlot);

                // Get epoch number
                (*NodeTipObj)->TryGetStringField(TEXT("epoch_number"), NetworkInfo.NodeTipEpoch);
            }

            // Parse node era
            JsonResponse->TryGetStringField(TEXT("node_era"), NetworkInfo.NodeEra);

            OnComplete.ExecuteIfBound(NetworkInfo);
        });

    // Process the request
    HttpRequest->ProcessRequest();
    return true;
}

float UCardanoBlueprintLibrary::LovelaceToAda(const int64 Lovelace)
{
    return Lovelace / 1000000.0f;
}

int64 UCardanoBlueprintLibrary::AdaToLovelace(const float Ada)
{
    return static_cast<int64>(Ada * 1000000.0f);
}

FString UCardanoBlueprintLibrary::DecodeCardanoAssetName(const FString& HexEncodedAssetName)
{
    // Input validation
    if (HexEncodedAssetName.IsEmpty())
    {
        return FString();
    }

    // Special case for lovelace
    if (HexEncodedAssetName.Equals(TEXT("lovelace"), ESearchCase::IgnoreCase))
    {
        return TEXT("ADA");
    }

    // Known ticker symbols and special mappings
    TMap<FString, FString> SpecialMappings = {
        {TEXT("HOSKY"), TEXT("HOSKY")},
        {TEXT("SNEK"), TEXT("SNEK")},
        {TEXT("MIN"), TEXT("MIN")},
        {TEXT("TOKE"), TEXT("TOKE")},
        {TEXT("DjedMicroUSD"), TEXT("Djed-USD")},
        {TEXT("0014df104372797374616c204672616773"), TEXT("Crystal Frags")},
        {TEXT("0014df104c6174654e69746553637269707473204c4c43"), TEXT("LateNiteScripts LLC")},
        {TEXT("0014df105553444d"), TEXT("USDM")},
        {TEXT("82e2b1fd27a7712a1a9cf750dfbea1a5778611b20e06dd6a611df7a643f8cb75"), TEXT("MINv2LP")}
    };

    // Check if it's a known mapping
    if (SpecialMappings.Contains(HexEncodedAssetName))
    {
        return SpecialMappings[HexEncodedAssetName];
    }

    // Convert hex to bytes
    TArray<uint8> Bytes;
    for (int32 i = 0; i < HexEncodedAssetName.Len(); i += 2)
    {
        if (i + 1 >= HexEncodedAssetName.Len())
            break;

        uint8 Byte = 0;
        TCHAR HighNibble = HexEncodedAssetName[i];
        TCHAR LowNibble = HexEncodedAssetName[i + 1];

        // Hex conversion logic
        if ('0' <= HighNibble && HighNibble <= '9')
            Byte = (HighNibble - '0') << 4;
        else if ('a' <= HighNibble && HighNibble <= 'f')
            Byte = (HighNibble - 'a' + 10) << 4;
        else if ('A' <= HighNibble && HighNibble <= 'F')
            Byte = (HighNibble - 'A' + 10) << 4;
        else
            continue;

        if ('0' <= LowNibble && LowNibble <= '9')
            Byte |= (LowNibble - '0');
        else if ('a' <= LowNibble && LowNibble <= 'f')
            Byte |= (LowNibble - 'a' + 10);
        else if ('A' <= LowNibble && LowNibble <= 'F')
            Byte |= (LowNibble - 'A' + 10);
        else
            continue;

        Bytes.Add(Byte);
    }

    // Debug logging
    FString ByteStr;
    for (uint8 Byte : Bytes)
    {
        ByteStr += FString::Printf(TEXT("%02X "), Byte);
    }
    UE_LOG(LogTemp, Warning, TEXT("Decoding Asset Name: %s, Bytes: %s"), *HexEncodedAssetName, *ByteStr);

    // Convert bytes to string, only if all bytes are printable ASCII
    FString Result;
    bool bIsPrintable = true;

    for (uint8 Byte : Bytes)
    {
        // Check if byte is printable ASCII
        if (Byte >= 32 && Byte <= 126)
        {
            Result.AppendChar(static_cast<TCHAR>(Byte));
        }
        else
        {
            bIsPrintable = false;
            break;
        }
    }

    // If all bytes are printable, return decoded string
    if (bIsPrintable && !Result.IsEmpty())
    {
        UE_LOG(LogTemp, Warning, TEXT("Decoded to printable string: %s"), *Result);
        return Result;
    }

    // If not printable or empty, return formatted hex string
    UE_LOG(LogTemp, Warning, TEXT("Could not decode to printable string, returning original: %s"), *HexEncodedAssetName);
    return HexEncodedAssetName;
}