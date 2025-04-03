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
#include <cardano/transaction_builder/transaction_builder.h>
#include <cardano/address/base_address.h>
#include <cardano/key_handlers/software_secure_key_handler.h>
#include "cardano/key_handlers/secure_key_handler.h"
#include "Misc/Paths.h"
#include "Misc/OutputDeviceDebug.h"
#include <cardano/cardano.h>
#include <curl/curl.h>
#include <cardano/provider_factory.h>
#include <sodium.h>
#include <cardano/blockfrost/common/blockfrost_url_builders.h>

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

    FString SanitizedPassword = Password.TrimStartAndEnd();
    const char* PassphraseUtf8 = TCHAR_TO_UTF8(*SanitizedPassword);
    UE_LOG(LogTemp, Warning, TEXT("Using passphrase: %s"), PassphraseUtf8);

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

void UCardanoBlueprintLibrary::SendLovelaceWithBlockfrost(
    const FString& ReceiverAddress,
    int64 AmountLovelace,
    const FString& BlockfrostApiKey,
    ECardanoNetwork NetworkType,
    const TArray<FString>& MnemonicWords,
    const FString& Password,
    FTransactionResult& OutResult,
    const FOnTransactionCompleted& OnComplete)
{
    // Initialize the result
    OutResult.bSuccess = false;
    OutResult.ErrorMessage = FString();
    OutResult.TransactionId = FString();

    // 1. Validate inputs
    if (ReceiverAddress.IsEmpty() || BlockfrostApiKey.IsEmpty() || AmountLovelace <= 0 ||
        MnemonicWords.Num() != 24 || Password.IsEmpty())
    {
        OutResult.ErrorMessage = TEXT("Invalid input parameters");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // ADD THESE LINES HERE - Disable SSL verification for testing
    //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);  // More explicit curl option
    //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);  // More explicit curl option
    //UE_LOG(LogTemp, Warning, TEXT("SSL verification disabled for testing"));

    // 2. Map network type enum to network magic constant
    cardano_network_id_t networkId;
    cardano_network_magic_t networkMagic;

    switch (NetworkType)
    {
    case ECardanoNetwork::Mainnet:
        networkId = CARDANO_NETWORK_ID_MAIN_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_MAINNET;
        break;
    case ECardanoNetwork::Preprod:
        networkId = CARDANO_NETWORK_ID_TEST_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_PREPROD;
        break;
    case ECardanoNetwork::Preview:
        networkId = CARDANO_NETWORK_ID_TEST_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_PREVIEW;
        break;
    default:
        networkId = CARDANO_NETWORK_ID_TEST_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_PREPROD; // Default to Preprod
        break;
    }

    // Log network configuration
    UE_LOG(LogTemp, Log, TEXT("Using Blockfrost with network ID: %d, network magic: %d"), networkId, networkMagic);
    UE_LOG(LogTemp, Log, TEXT("API Key length: %d"), BlockfrostApiKey.Len());

    // 3. Create Blockfrost provider
    cardano_provider_t* provider = nullptr;
    const char* apiKey = TCHAR_TO_UTF8(*BlockfrostApiKey);

    cardano_error_t result = create_blockfrost_provider(
        networkMagic,
        apiKey,
        FCStringAnsi::Strlen(apiKey),
        &provider
    );

    if (result != CARDANO_SUCCESS)
    {
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to create provider: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 4. Convert mnemonic words to entropy
    const char* wordArray[24] = { nullptr };
    for (int32 i = 0; i < 24; i++)
    {
        FString SanitizedWord = MnemonicWords[i].TrimStartAndEnd().ToLower();
        char* word = (char*)FMemory::Malloc(SanitizedWord.Len() + 1);
        if (!word)
        {
            // Clean up previously allocated strings
            for (int32 j = 0; j < i; j++)
            {
                FMemory::Free((void*)wordArray[j]);
            }
            cardano_provider_unref(&provider);
            OutResult.ErrorMessage = TEXT("Memory allocation failed");
            OnComplete.ExecuteIfBound(OutResult);
            return;
        }

        FCStringAnsi::Strcpy(word, SanitizedWord.Len() + 1, TCHAR_TO_UTF8(*SanitizedWord));
        wordArray[i] = word;
    }

    // Convert to entropy
    byte_t entropy[64] = { 0 };
    size_t entropy_size = 0;

    result = cardano_bip39_mnemonic_words_to_entropy(
        wordArray,
        24,
        entropy,
        sizeof(entropy),
        &entropy_size
    );

    // Free allocated word strings
    for (int32 i = 0; i < 24; i++)
    {
        FMemory::Free((void*)wordArray[i]);
    }

    if (result != CARDANO_SUCCESS)
    {
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to convert mnemonic to entropy: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 5. Create secure key handler
    cardano_secure_key_handler_t* keyHandler = nullptr;
    const char* passwordUtf8 = TCHAR_TO_UTF8(*Password);

    result = cardano_software_secure_key_handler_new(
        entropy,
        entropy_size,
        (const byte_t*)passwordUtf8,
        FCStringAnsi::Strlen(passwordUtf8),
        &GetPassphrase,
        &keyHandler
    );

    if (result != CARDANO_SUCCESS)
    {
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to create key handler: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 6. Get protocol parameters with additional error handling
    cardano_protocol_parameters_t* protocolParams = nullptr;
    UE_LOG(LogTemp, Log, TEXT("Requesting protocol parameters from Blockfrost..."));

    result = cardano_provider_get_parameters(provider, &protocolParams);

    if (result != CARDANO_SUCCESS)
    {
        const char* providerError = cardano_provider_get_last_error(provider);
        FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to get protocol parameters: %s\nDetails: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    UE_LOG(LogTemp, Log, TEXT("Successfully retrieved protocol parameters"));

    // 7. Create payment address
    const cardano_account_derivation_path_t ACCOUNT_PATH = {
        1852U | 0x80000000,
        1815U | 0x80000000,
        0U
    };

    cardano_address_t* paymentAddress = create_address_from_derivation_paths(
        keyHandler,
        ACCOUNT_PATH,
        0,  // payment_index
        0   // stake_index
    );

    if (!paymentAddress)
    {
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = TEXT("Failed to create payment address");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // Log the address we're sending from
    UE_LOG(LogTemp, Log, TEXT("Sending from address: %s"), UTF8_TO_TCHAR(cardano_address_get_string(paymentAddress)));

    // 8. Get UTXOs for the address
    cardano_utxo_list_t* utxoList = nullptr;
    result = cardano_provider_get_unspent_outputs(provider, paymentAddress, &utxoList);

    if (result != CARDANO_SUCCESS)
    {
        const char* providerError = cardano_provider_get_last_error(provider);
        FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to get UTXOs: %s\nDetails: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 9. Create transaction builder
    cardano_tx_builder_t* txBuilder = cardano_tx_builder_new(protocolParams, provider);

    if (!txBuilder)
    {
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = TEXT("Failed to create transaction builder");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 10. Set up transaction parameters
    cardano_tx_builder_set_utxos(txBuilder, utxoList);
    cardano_tx_builder_set_change_address(txBuilder, paymentAddress);

    // Set time-to-live to 2 hours from now
    uint64_t invalidAfter = FDateTime::UtcNow().ToUnixTimestamp() + (2 * 60 * 60);
    cardano_tx_builder_set_invalid_after_ex(txBuilder, invalidAfter);

    // Add the payment to receiver
    const char* receiverAddressUtf8 = TCHAR_TO_UTF8(*ReceiverAddress);

    UE_LOG(LogTemp, Log, TEXT("Sending %lld lovelace to %s"), AmountLovelace, *ReceiverAddress);

    // Call the function without trying to assign its return value to result
    cardano_tx_builder_send_lovelace_ex(
        txBuilder,
        receiverAddressUtf8,
        FCStringAnsi::Strlen(receiverAddressUtf8),
        AmountLovelace
    );

    // Check for errors after calling the function by getting the last error
    const char* builderError = cardano_tx_builder_get_last_error(txBuilder);
    if (builderError && strlen(builderError) > 0)
    {
        FString errorDetails = UTF8_TO_TCHAR(builderError);

        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to add payment output: %s"), *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 11. Build the transaction
    cardano_transaction_t* transaction = nullptr;
    result = cardano_tx_builder_build(txBuilder, &transaction);

    if (result != CARDANO_SUCCESS)
    {
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to build transaction: %s\n%s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)),
            UTF8_TO_TCHAR(cardano_tx_builder_get_last_error(txBuilder)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 12. Sign transaction
    const cardano_derivation_path_t SIGNER_PATH = {
        1852U | 0x80000000,
        1815U | 0x80000000,
        0U,
        0U,
        0U
    };

    cardano_vkey_witness_set_t* vkey = nullptr;
    result = cardano_secure_key_handler_bip32_sign_transaction(
        keyHandler,
        transaction,
        &SIGNER_PATH,
        1,
        &vkey
    );

    if (result != CARDANO_SUCCESS)
    {
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to sign transaction: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    result = cardano_transaction_apply_vkey_witnesses(transaction, vkey);
    cardano_vkey_witness_set_unref(&vkey);

    if (result != CARDANO_SUCCESS)
    {
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to apply witnesses: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 13. Submit transaction
    cardano_blake2b_hash_t* txId = nullptr;
    result = cardano_provider_submit_transaction(provider, transaction, &txId);

    // Additional debugging
    if (result != CARDANO_SUCCESS)
    {
        // Serialize the transaction to CBOR for inspection
        cardano_cbor_writer_t* writer = cardano_cbor_writer_new();
        if (writer)
        {
            size_t cbor_size = 0;
            result = cardano_transaction_to_cbor(transaction, writer);
            if (result == CARDANO_SUCCESS)
            {
                cbor_size = cardano_cbor_writer_get_encode_size(writer);

                // Allocate buffer for CBOR
                byte_t* cbor_data = (byte_t*)FMemory::Malloc(cbor_size);
                if (cbor_data)
                {
                    result = cardano_cbor_writer_encode(writer, cbor_data, cbor_size);

                    if (result == CARDANO_SUCCESS)
                    {
                        // Convert CBOR to hex string for logging
                        char* cbor_hex = (char*)FMemory::Malloc(cbor_size * 2 + 1);
                        if (cbor_hex)
                        {
                            for (size_t i = 0; i < cbor_size; i++)
                            {
                                sprintf(cbor_hex + i * 2, "%02x", cbor_data[i]);
                            }

                            UE_LOG(LogTemp, Error, TEXT("Transaction CBOR Hex (size %d): %s"),
                                cbor_size, UTF8_TO_TCHAR(cbor_hex));

                            FMemory::Free(cbor_hex);
                        }
                    }

                    FMemory::Free(cbor_data);
                }
            }

            cardano_cbor_writer_unref(&writer);
        }

        // Get detailed error information
        const char* providerError = cardano_provider_get_last_error(provider);
        FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

        // Log transaction body details
        cardano_transaction_body_t* body = cardano_transaction_get_body(transaction);
        if (body)
        {
            // Log input count
            cardano_transaction_input_set_t* inputs = cardano_transaction_body_get_inputs(body);
            size_t input_count = cardano_transaction_input_set_get_length(inputs);

            // Log output count
            cardano_transaction_output_list_t* outputs = cardano_transaction_body_get_outputs(body);
            size_t output_count = cardano_transaction_output_list_get_length(outputs);

            UE_LOG(LogTemp, Error, TEXT("Transaction Details:"));
            UE_LOG(LogTemp, Error, TEXT("Input Count: %d"), input_count);
            UE_LOG(LogTemp, Error, TEXT("Output Count: %d"), output_count);

            cardano_transaction_input_set_unref(&inputs);
            cardano_transaction_output_list_unref(&outputs);
            cardano_transaction_body_unref(&body);
        }

        // Cleanup and error handling remains the same
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to submit transaction: %s\nDetails: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)),
            *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 14. Await confirmation
    bool confirmed = false;
    const uint64_t CONFIRM_TIMEOUT_MS = 240000U; // 4 minutes

    result = cardano_provider_confirm_transaction(provider, txId, CONFIRM_TIMEOUT_MS, &confirmed);

    // Get transaction ID as string
    if (txId != nullptr)
    {
        const size_t txIdHexSize = cardano_blake2b_hash_get_hex_size(txId);
        char* txIdHex = (char*)FMemory::Malloc(txIdHexSize);

        if (txIdHex != nullptr)
        {
            if (cardano_blake2b_hash_to_hex(txId, txIdHex, txIdHexSize) == CARDANO_SUCCESS)
            {
                OutResult.TransactionId = UTF8_TO_TCHAR(txIdHex);
                UE_LOG(LogTemp, Log, TEXT("Transaction ID: %s"), *OutResult.TransactionId);
            }
            FMemory::Free(txIdHex);
        }

        cardano_blake2b_hash_unref(&txId);
    }

    // Set success based on confirmation
    OutResult.bSuccess = confirmed;

    if (!confirmed && result != CARDANO_SUCCESS)
    {
        OutResult.ErrorMessage = FString::Printf(TEXT("Transaction not confirmed: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
    }
    else if (confirmed)
    {
        UE_LOG(LogTemp, Log, TEXT("Transaction confirmed successfully"));
    }

    // Clean up
    cardano_transaction_unref(&transaction);
    cardano_tx_builder_unref(&txBuilder);
    cardano_utxo_list_unref(&utxoList);
    cardano_address_unref(&paymentAddress);
    cardano_protocol_parameters_unref(&protocolParams);
    cardano_secure_key_handler_unref(&keyHandler);
    cardano_provider_unref(&provider);

    // Notify completion
    OnComplete.ExecuteIfBound(OutResult);
}

void UCardanoBlueprintLibrary::AsyncSendLovelaceWithBlockfrost(
    const FString& ReceiverAddress,
    int64 AmountLovelace,
    const FString& BlockfrostApiKey,
    ECardanoNetwork NetworkType,
    const TArray<FString>& MnemonicWords,
    const FString& Password,
    FTransactionResult& OutResult,
    const FOnTransactionCompleted& OnComplete,
    const FString& CustomBaseUrl)
{
    // Initialize the result
    OutResult.bSuccess = false;
    OutResult.ErrorMessage = FString();
    OutResult.TransactionId = FString();

    // 1. Validate inputs
    if (ReceiverAddress.IsEmpty() || BlockfrostApiKey.IsEmpty() || AmountLovelace <= 0 ||
        MnemonicWords.Num() != 24 || Password.IsEmpty())
    {
        OutResult.ErrorMessage = TEXT("Invalid input parameters");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // If a custom base URL is provided, set it
    if (!CustomBaseUrl.IsEmpty())
    {
        const char* UrlStr = TCHAR_TO_UTF8(*CustomBaseUrl);
        cardano_blockfrost_set_custom_base_url(UrlStr, FCStringAnsi::Strlen(UrlStr));
    }
    else
    {
        // Reset to default URLs if no custom URL is provided
        cardano_blockfrost_set_custom_base_url(nullptr, 0);
    }

    // Create a new async task
    AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask, [=]() {
        FTransactionResult Result;
        Result.bSuccess = false;
        Result.ErrorMessage = FString();
        Result.TransactionId = FString();

        // 2. Map network type enum to network magic constant
        cardano_network_id_t networkId;
        cardano_network_magic_t networkMagic;

        switch (NetworkType)
        {
        case ECardanoNetwork::Mainnet:
            networkId = CARDANO_NETWORK_ID_MAIN_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_MAINNET;
            break;
        case ECardanoNetwork::Preprod:
            networkId = CARDANO_NETWORK_ID_TEST_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_PREPROD;
            break;
        case ECardanoNetwork::Preview:
            networkId = CARDANO_NETWORK_ID_TEST_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_PREVIEW;
            break;
        default:
            networkId = CARDANO_NETWORK_ID_TEST_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_PREPROD; // Default to Preprod
            break;
        }

        // Log network configuration
        UE_LOG(LogTemp, Log, TEXT("Using Blockfrost with network ID: %d, network magic: %d"), networkId, networkMagic);
        UE_LOG(LogTemp, Log, TEXT("API Key length: %d"), BlockfrostApiKey.Len());

        // 3. Create Blockfrost provider
        cardano_provider_t* provider = nullptr;
        const char* apiKey = TCHAR_TO_UTF8(*BlockfrostApiKey);

        cardano_error_t result = create_blockfrost_provider(
            networkMagic,
            apiKey,
            FCStringAnsi::Strlen(apiKey),
            &provider
        );

        if (result != CARDANO_SUCCESS)
        {
            Result.ErrorMessage = FString::Printf(TEXT("Failed to create provider: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 4. Convert mnemonic words to entropy
        const char* wordArray[24] = { nullptr };
        for (int32 i = 0; i < 24; i++)
        {
            FString SanitizedWord = MnemonicWords[i].TrimStartAndEnd().ToLower();
            char* word = (char*)FMemory::Malloc(SanitizedWord.Len() + 1);
            if (!word)
            {
                // Clean up previously allocated strings
                for (int32 j = 0; j < i; j++)
                {
                    FMemory::Free((void*)wordArray[j]);
                }
                cardano_provider_unref(&provider);
                Result.ErrorMessage = TEXT("Memory allocation failed");

                // Return to game thread to execute the callback
                AsyncTask(ENamedThreads::GameThread, [=]() {
                    OnComplete.ExecuteIfBound(Result);
                    });
                return;
            }

            FCStringAnsi::Strcpy(word, SanitizedWord.Len() + 1, TCHAR_TO_UTF8(*SanitizedWord));
            wordArray[i] = word;
        }

        // Convert to entropy
        byte_t entropy[64] = { 0 };
        size_t entropy_size = 0;

        result = cardano_bip39_mnemonic_words_to_entropy(
            wordArray,
            24,
            entropy,
            sizeof(entropy),
            &entropy_size
        );

        // Free allocated word strings
        for (int32 i = 0; i < 24; i++)
        {
            FMemory::Free((void*)wordArray[i]);
        }

        if (result != CARDANO_SUCCESS)
        {
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to convert mnemonic to entropy: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 5. Create secure key handler
        cardano_secure_key_handler_t* keyHandler = nullptr;
        const char* passwordUtf8 = TCHAR_TO_UTF8(*Password);

        result = cardano_software_secure_key_handler_new(
            entropy,
            entropy_size,
            (const byte_t*)passwordUtf8,
            FCStringAnsi::Strlen(passwordUtf8),
            &GetPassphrase,
            &keyHandler
        );

        if (result != CARDANO_SUCCESS)
        {
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to create key handler: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 6. Get protocol parameters
        cardano_protocol_parameters_t* protocolParams = nullptr;
        UE_LOG(LogTemp, Log, TEXT("Requesting protocol parameters from Blockfrost..."));

        result = cardano_provider_get_parameters(provider, &protocolParams);

        if (result != CARDANO_SUCCESS)
        {
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to get protocol parameters: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        UE_LOG(LogTemp, Log, TEXT("Successfully retrieved protocol parameters"));

        // 7. Create payment address
        const cardano_account_derivation_path_t ACCOUNT_PATH = {
            1852U | 0x80000000,
            1815U | 0x80000000,
            0U
        };

        cardano_address_t* paymentAddress = create_address_from_derivation_paths(
            keyHandler,
            ACCOUNT_PATH,
            0,  // payment_index
            0   // stake_index
        );

        if (!paymentAddress)
        {
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = TEXT("Failed to create payment address");

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // Log the address we're sending from
        UE_LOG(LogTemp, Log, TEXT("Sending from address: %s"), UTF8_TO_TCHAR(cardano_address_get_string(paymentAddress)));

        // 8. Get UTXOs for the address
        cardano_utxo_list_t* utxoList = nullptr;
        result = cardano_provider_get_unspent_outputs(provider, paymentAddress, &utxoList);

        if (result != CARDANO_SUCCESS)
        {
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to get UTXOs: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 9. Create transaction builder
        cardano_tx_builder_t* txBuilder = cardano_tx_builder_new(protocolParams, provider);

        if (!txBuilder)
        {
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = TEXT("Failed to create transaction builder");

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 10. Set up transaction parameters
        cardano_tx_builder_set_utxos(txBuilder, utxoList);
        cardano_tx_builder_set_change_address(txBuilder, paymentAddress);

        // Set time-to-live to 2 hours from now
        uint64_t invalidAfter = FDateTime::UtcNow().ToUnixTimestamp() + (2 * 60 * 60);
        cardano_tx_builder_set_invalid_after_ex(txBuilder, invalidAfter);

        // Add the payment to receiver
        const char* receiverAddressUtf8 = TCHAR_TO_UTF8(*ReceiverAddress);

        UE_LOG(LogTemp, Log, TEXT("Sending %lld lovelace to %s"), AmountLovelace, *ReceiverAddress);

        // Call the function to add the payment
        cardano_tx_builder_send_lovelace_ex(
            txBuilder,
            receiverAddressUtf8,
            FCStringAnsi::Strlen(receiverAddressUtf8),
            AmountLovelace
        );

        // Check for errors after calling the function
        const char* builderError = cardano_tx_builder_get_last_error(txBuilder);
        if (builderError && strlen(builderError) > 0)
        {
            FString errorDetails = UTF8_TO_TCHAR(builderError);

            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to add payment output: %s"), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 11. Build the transaction
        cardano_transaction_t* transaction = nullptr;
        result = cardano_tx_builder_build(txBuilder, &transaction);

        if (result != CARDANO_SUCCESS)
        {
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to build transaction: %s\n%s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)),
                UTF8_TO_TCHAR(cardano_tx_builder_get_last_error(txBuilder)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 12. Sign transaction
        const cardano_derivation_path_t SIGNER_PATH = {
            1852U | 0x80000000,
            1815U | 0x80000000,
            0U,
            0U,
            0U
        };

        cardano_vkey_witness_set_t* vkey = nullptr;
        result = cardano_secure_key_handler_bip32_sign_transaction(
            keyHandler,
            transaction,
            &SIGNER_PATH,
            1,
            &vkey
        );

        if (result != CARDANO_SUCCESS)
        {
            cardano_transaction_unref(&transaction);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to sign transaction: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        result = cardano_transaction_apply_vkey_witnesses(transaction, vkey);
        cardano_vkey_witness_set_unref(&vkey);

        if (result != CARDANO_SUCCESS)
        {
            cardano_transaction_unref(&transaction);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to apply witnesses: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 13. Submit transaction
        cardano_blake2b_hash_t* txId = nullptr;
        result = cardano_provider_submit_transaction(provider, transaction, &txId);

        if (result != CARDANO_SUCCESS)
        {
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_transaction_unref(&transaction);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to submit transaction: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)),
                *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 14. Await confirmation
        bool confirmed = false;
        const uint64_t CONFIRM_TIMEOUT_MS = 240000U; // 4 minutes

        result = cardano_provider_confirm_transaction(provider, txId, CONFIRM_TIMEOUT_MS, &confirmed);

        // Get transaction ID as string
        if (txId != nullptr)
        {
            const size_t txIdHexSize = cardano_blake2b_hash_get_hex_size(txId);
            char* txIdHex = (char*)FMemory::Malloc(txIdHexSize);

            if (txIdHex != nullptr)
            {
                if (cardano_blake2b_hash_to_hex(txId, txIdHex, txIdHexSize) == CARDANO_SUCCESS)
                {
                    Result.TransactionId = UTF8_TO_TCHAR(txIdHex);
                    UE_LOG(LogTemp, Log, TEXT("Transaction ID: %s"), *Result.TransactionId);
                }
                FMemory::Free(txIdHex);
            }

            cardano_blake2b_hash_unref(&txId);
        }

        // Set success based on confirmation
        Result.bSuccess = confirmed;

        if (!confirmed && result != CARDANO_SUCCESS)
        {
            Result.ErrorMessage = FString::Printf(TEXT("Transaction not confirmed: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));
        }
        else if (confirmed)
        {
            UE_LOG(LogTemp, Log, TEXT("Transaction confirmed successfully"));
        }

        // Clean up
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        // Return to game thread to execute the callback
        AsyncTask(ENamedThreads::GameThread, [=]() {
            cardano_blockfrost_set_custom_base_url(nullptr, 0);
            OnComplete.ExecuteIfBound(Result);
            });
        });
}

void UCardanoBlueprintLibrary::EstimateTransactionFeeOffline(
    const TArray<FTokenTransfer>& Transfers,
    bool bIncludeMetadata,
    FTransactionFeeResult& OutResult)
{
    // Base transaction fee in lovelace (0.17 ADA)
    int64 EstimatedFee = 170000;

    // Token count for fee adjustment
    int32 TokenCount = 0;
    int64 TotalAda = 0;

    // Analyze the transfers
    for (const FTokenTransfer& Transfer : Transfers)
    {
        if (Transfer.PolicyId.IsEmpty())
        {
            // This is ADA/lovelace
            TotalAda += Transfer.Amount;
        }
        else
        {
            // This is a native token
            TokenCount++;
        }
    }

    // Add fee based on complexity

    // Each additional token adds to the transaction size and complexity
    if (TokenCount > 0)
    {
        // Base increase for having any token (min ADA requirement)
        EstimatedFee += 30000;

        // Additional increase per token
        EstimatedFee += TokenCount * 5000;
    }

    // Larger ADA amounts typically involve more UTXOs, increasing fee
    if (TotalAda > 10000000) // More than 10 ADA
    {
        EstimatedFee += 10000;
    }

    // Metadata adds to transaction size
    if (bIncludeMetadata)
    {
        EstimatedFee += 15000;
    }

    // Add safety margin (20%)
    EstimatedFee = static_cast<int64>(EstimatedFee * 1.2);

    // Set the result
    OutResult.bSuccess = true;
    OutResult.EstimatedFee = EstimatedFee;
}

void UCardanoBlueprintLibrary::AsyncEstimateTransactionFeeOffline(
    const TArray<FTokenTransfer>& Transfers,
    bool bIncludeMetadata,
    const FOnFeeEstimationComplete& OnComplete)
{
    // Create a copy of the transfers array to capture by value
    TArray<FTokenTransfer> TransfersCopy = Transfers;

    // Create the async task on a background thread
    AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask, [TransfersCopy, bIncludeMetadata, OnComplete]() {
        // Base transaction fee in lovelace (0.17 ADA)
        int64 EstimatedFee = 170000;

        // Token count for fee adjustment
        int32 TokenCount = 0;
        int64 TotalAda = 0;

        // Analyze the transfers
        for (const FTokenTransfer& Transfer : TransfersCopy)
        {
            if (Transfer.PolicyId.IsEmpty())
            {
                // This is ADA/lovelace
                TotalAda += Transfer.Amount;
            }
            else
            {
                // This is a native token
                TokenCount++;
            }
        }

        // Add fee based on complexity

        // Each additional token adds to the transaction size and complexity
        if (TokenCount > 0)
        {
            // Base increase for having any token (min ADA requirement)
            EstimatedFee += 30000;

            // Additional increase per token
            EstimatedFee += TokenCount * 5000;
        }

        // Larger ADA amounts typically involve more UTXOs, increasing fee
        if (TotalAda > 10000000) // More than 10 ADA
        {
            EstimatedFee += 10000;
        }

        // Metadata adds to transaction size
        if (bIncludeMetadata)
        {
            EstimatedFee += 15000;
        }

        // Add safety margin (20%)
        EstimatedFee = static_cast<int64>(EstimatedFee * 1.2);

        // Create and set result
        FTransactionFeeResult Result;
        Result.bSuccess = true;
        Result.EstimatedFee = EstimatedFee;

        // Return to game thread to execute callback
        AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
            OnComplete.ExecuteIfBound(Result);
            });
        });
}

void UCardanoBlueprintLibrary::SendTokensWithBlockfrost(
    const FString& ReceiverAddress,
    TMap<FString, int64> TokensToSend,
    const FString& BlockfrostApiKey,
    ECardanoNetwork NetworkType,
    const TArray<FString>& MnemonicWords,
    const FString& Password,
    FTransactionResult& OutResult,
    const FOnTransactionCompleted& OnComplete)
{
    // Initialize the result
    OutResult.bSuccess = false;
    OutResult.ErrorMessage = FString();
    OutResult.TransactionId = FString();

    // 1. Validate inputs
    if (ReceiverAddress.IsEmpty() || BlockfrostApiKey.IsEmpty() ||
        MnemonicWords.Num() != 24 || Password.IsEmpty() || TokensToSend.Num() == 0)
    {
        OutResult.ErrorMessage = TEXT("Invalid input parameters");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 2. Map network type enum to network magic constant
    cardano_network_id_t networkId;
    cardano_network_magic_t networkMagic;

    switch (NetworkType)
    {
    case ECardanoNetwork::Mainnet:
        networkId = CARDANO_NETWORK_ID_MAIN_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_MAINNET;
        break;
    case ECardanoNetwork::Preprod:
        networkId = CARDANO_NETWORK_ID_TEST_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_PREPROD;
        break;
    case ECardanoNetwork::Preview:
        networkId = CARDANO_NETWORK_ID_TEST_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_PREVIEW;
        break;
    default:
        networkId = CARDANO_NETWORK_ID_TEST_NET;
        networkMagic = CARDANO_NETWORK_MAGIC_PREPROD; // Default to Preprod
        break;
    }

    // Log network configuration
    UE_LOG(LogTemp, Log, TEXT("Using Blockfrost with network ID: %d, network magic: %d"), networkId, networkMagic);
    UE_LOG(LogTemp, Log, TEXT("API Key length: %d"), BlockfrostApiKey.Len());

    // 3. Create Blockfrost provider
    cardano_provider_t* provider = nullptr;
    const char* apiKey = TCHAR_TO_UTF8(*BlockfrostApiKey);

    cardano_error_t result = create_blockfrost_provider(
        networkMagic,
        apiKey,
        FCStringAnsi::Strlen(apiKey),
        &provider
    );

    if (result != CARDANO_SUCCESS)
    {
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to create provider: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 4. Convert mnemonic words to entropy
    const char* wordArray[24] = { nullptr };
    for (int32 i = 0; i < 24; i++)
    {
        FString SanitizedWord = MnemonicWords[i].TrimStartAndEnd().ToLower();
        char* word = (char*)FMemory::Malloc(SanitizedWord.Len() + 1);
        if (!word)
        {
            // Clean up previously allocated strings
            for (int32 j = 0; j < i; j++)
            {
                FMemory::Free((void*)wordArray[j]);
            }
            cardano_provider_unref(&provider);
            OutResult.ErrorMessage = TEXT("Memory allocation failed");
            OnComplete.ExecuteIfBound(OutResult);
            return;
        }

        FCStringAnsi::Strcpy(word, SanitizedWord.Len() + 1, TCHAR_TO_UTF8(*SanitizedWord));
        wordArray[i] = word;
    }

    // Convert to entropy
    byte_t entropy[64] = { 0 };
    size_t entropy_size = 0;

    result = cardano_bip39_mnemonic_words_to_entropy(
        wordArray,
        24,
        entropy,
        sizeof(entropy),
        &entropy_size
    );

    // Free allocated word strings
    for (int32 i = 0; i < 24; i++)
    {
        FMemory::Free((void*)wordArray[i]);
    }

    if (result != CARDANO_SUCCESS)
    {
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to convert mnemonic to entropy: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 5. Create secure key handler
    cardano_secure_key_handler_t* keyHandler = nullptr;
    const char* passwordUtf8 = TCHAR_TO_UTF8(*Password);

    result = cardano_software_secure_key_handler_new(
        entropy,
        entropy_size,
        (const byte_t*)passwordUtf8,
        FCStringAnsi::Strlen(passwordUtf8),
        &GetPassphrase,
        &keyHandler
    );

    if (result != CARDANO_SUCCESS)
    {
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to create key handler: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 6. Get protocol parameters
    cardano_protocol_parameters_t* protocolParams = nullptr;
    UE_LOG(LogTemp, Log, TEXT("Requesting protocol parameters from Blockfrost..."));

    result = cardano_provider_get_parameters(provider, &protocolParams);

    if (result != CARDANO_SUCCESS)
    {
        const char* providerError = cardano_provider_get_last_error(provider);
        FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to get protocol parameters: %s\nDetails: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    UE_LOG(LogTemp, Log, TEXT("Successfully retrieved protocol parameters"));

    // 7. Create payment address
    const cardano_account_derivation_path_t ACCOUNT_PATH = {
        1852U | 0x80000000,
        1815U | 0x80000000,
        0U
    };

    cardano_address_t* paymentAddress = create_address_from_derivation_paths(
        keyHandler,
        ACCOUNT_PATH,
        0,  // payment_index
        0   // stake_index
    );

    if (!paymentAddress)
    {
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = TEXT("Failed to create payment address");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // Log the address we're sending from
    UE_LOG(LogTemp, Log, TEXT("Sending from address: %s"), UTF8_TO_TCHAR(cardano_address_get_string(paymentAddress)));

    // 8. Get UTXOs for the address
    cardano_utxo_list_t* utxoList = nullptr;

    // Always get all UTXOs
    result = cardano_provider_get_unspent_outputs(provider, paymentAddress, &utxoList);

    if (result != CARDANO_SUCCESS)
    {
        const char* providerError = cardano_provider_get_last_error(provider);
        FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to get UTXOs: %s\nDetails: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 9. Create transaction builder
    cardano_tx_builder_t* txBuilder = cardano_tx_builder_new(protocolParams, provider);

    if (!txBuilder)
    {
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);
        OutResult.ErrorMessage = TEXT("Failed to create transaction builder");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 10. Set up transaction parameters
    cardano_tx_builder_set_utxos(txBuilder, utxoList);
    cardano_tx_builder_set_change_address(txBuilder, paymentAddress);

    // Set time-to-live to 2 hours from now
    uint64_t invalidAfter = FDateTime::UtcNow().ToUnixTimestamp() + (2 * 60 * 60);
    cardano_tx_builder_set_invalid_after_ex(txBuilder, invalidAfter);

    // 11. Create value to send (ADA + tokens)
    cardano_value_t* sendValue = nullptr;
    result = cardano_value_new(0, nullptr, &sendValue); // Start with 0 lovelace

    if (result != CARDANO_SUCCESS)
    {
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to create value object: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // Flag to track if we have ADA in the transaction
    bool hasLovelace = false;
    int64 lovelaceAmount = 0;

    // First check if ADA (lovelace) is included
    for (auto& Token : TokensToSend)
    {
        if (Token.Key.Equals("lovelace", ESearchCase::IgnoreCase))
        {
            // Set the coin amount for ADA
            lovelaceAmount = Token.Value;
            hasLovelace = true;
            result = cardano_value_set_coin(sendValue, lovelaceAmount);
            if (result != CARDANO_SUCCESS)
            {
                cardano_value_unref(&sendValue);
                cardano_tx_builder_unref(&txBuilder);
                cardano_utxo_list_unref(&utxoList);
                cardano_address_unref(&paymentAddress);
                cardano_protocol_parameters_unref(&protocolParams);
                cardano_secure_key_handler_unref(&keyHandler);
                cardano_provider_unref(&provider);

                OutResult.ErrorMessage = FString::Printf(TEXT("Failed to set coin value: %s"),
                    UTF8_TO_TCHAR(cardano_error_to_string(result)));
                OnComplete.ExecuteIfBound(OutResult);
                return;
            }
            break; // Found lovelace, exit the loop
        }
    }

    // Ensure we have minimum ADA for token transfers if not specified
    if (!hasLovelace)
    {
        // Add minimum ADA required for native token transactions (typically ~2 ADA)
        // This is a simplification - in practice, calculate the exact minimum needed
        const int64 MIN_LOVELACE = 2000000; // 2 ADA in lovelace
        result = cardano_value_set_coin(sendValue, MIN_LOVELACE);
        lovelaceAmount = MIN_LOVELACE;

        if (result != CARDANO_SUCCESS)
        {
            cardano_value_unref(&sendValue);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            OutResult.ErrorMessage = FString::Printf(TEXT("Failed to set minimum lovelace amount: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));
            OnComplete.ExecuteIfBound(OutResult);
            return;
        }

        UE_LOG(LogTemp, Warning, TEXT("No ADA specified for transaction. Adding minimum of %lld lovelace (2 ADA)"), MIN_LOVELACE);
    }
    else if (lovelaceAmount < 1000000)
    {
        UE_LOG(LogTemp, Warning, TEXT("Low ADA amount (%lld lovelace) specified for transaction. This may be insufficient."), lovelaceAmount);
    }

    // Now add all the native tokens
    for (auto& Token : TokensToSend)
    {
        if (Token.Key.Equals("lovelace", ESearchCase::IgnoreCase))
        {
            continue; // Skip ADA, already handled above
        }

        // Parse token identifier
        TArray<FString> TokenParts;
        Token.Key.ParseIntoArray(TokenParts, TEXT("."), true);

        if (TokenParts.Num() != 2)
        {
            cardano_value_unref(&sendValue);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            OutResult.ErrorMessage = FString::Printf(TEXT("Invalid token format: %s. Expected 'policyId.assetName'"), *Token.Key);
            OnComplete.ExecuteIfBound(OutResult);
            return;
        }

        // Add token to value
        result = cardano_value_add_asset_ex(
            sendValue,
            TCHAR_TO_UTF8(*TokenParts[0]), TokenParts[0].Len(),
            TCHAR_TO_UTF8(*TokenParts[1]), TokenParts[1].Len(),
            Token.Value
        );

        if (result != CARDANO_SUCCESS)
        {
            cardano_value_unref(&sendValue);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            OutResult.ErrorMessage = FString::Printf(TEXT("Failed to add token %s: %s"),
                *Token.Key, UTF8_TO_TCHAR(cardano_error_to_string(result)));
            OnComplete.ExecuteIfBound(OutResult);
            return;
        }
    }

    // 12. Add output to the transaction
    const char* receiverAddressUtf8 = TCHAR_TO_UTF8(*ReceiverAddress);

    UE_LOG(LogTemp, Log, TEXT("Sending tokens to %s"), *ReceiverAddress);

    // Create a cardano_address_t from the receiver address string
    cardano_address_t* receiverAddress = nullptr;
    result = cardano_address_from_string(receiverAddressUtf8, strlen(receiverAddressUtf8), &receiverAddress);

    if (result != CARDANO_SUCCESS)
    {
        cardano_value_unref(&sendValue);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to parse receiver address: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // Send the value
    cardano_tx_builder_send_value(txBuilder, receiverAddress, sendValue);

    // Free sendValue and receiverAddress as they're no longer needed
    cardano_value_unref(&sendValue);
    cardano_address_unref(&receiverAddress);

    // Check for errors after sending value
    const char* builderError = cardano_tx_builder_get_last_error(txBuilder);
    if (builderError && strlen(builderError) > 0)
    {
        FString errorDetails = UTF8_TO_TCHAR(builderError);

        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to add output: %s"), *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 13. Build the transaction
    cardano_transaction_t* transaction = nullptr;
    result = cardano_tx_builder_build(txBuilder, &transaction);

    if (result != CARDANO_SUCCESS)
    {
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to build transaction: %s\n%s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)),
            UTF8_TO_TCHAR(cardano_tx_builder_get_last_error(txBuilder)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 14. Sign transaction
    const cardano_derivation_path_t SIGNER_PATH = {
        1852U | 0x80000000,
        1815U | 0x80000000,
        0U,
        0U,
        0U
    };

    cardano_vkey_witness_set_t* vkey = nullptr;
    result = cardano_secure_key_handler_bip32_sign_transaction(
        keyHandler,
        transaction,
        &SIGNER_PATH,
        1,
        &vkey
    );

    if (result != CARDANO_SUCCESS)
    {
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to sign transaction: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    result = cardano_transaction_apply_vkey_witnesses(transaction, vkey);
    cardano_vkey_witness_set_unref(&vkey);

    if (result != CARDANO_SUCCESS)
    {
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to apply witnesses: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 15. Submit transaction
    cardano_blake2b_hash_t* txId = nullptr;
    result = cardano_provider_submit_transaction(provider, transaction, &txId);

    if (result != CARDANO_SUCCESS)
    {
        // Get detailed error information from provider
        const char* providerError = cardano_provider_get_last_error(provider);
        FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        OutResult.ErrorMessage = FString::Printf(TEXT("Failed to submit transaction: %s\nDetails: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)),
            *errorDetails);
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // 16. Await confirmation
    bool confirmed = false;
    const uint64_t CONFIRM_TIMEOUT_MS = 240000U; // 4 minutes

    result = cardano_provider_confirm_transaction(provider, txId, CONFIRM_TIMEOUT_MS, &confirmed);

    // Get transaction ID as string
    if (txId != nullptr)
    {
        const size_t txIdHexSize = cardano_blake2b_hash_get_hex_size(txId);
        char* txIdHex = (char*)FMemory::Malloc(txIdHexSize);

        if (txIdHex != nullptr)
        {
            if (cardano_blake2b_hash_to_hex(txId, txIdHex, txIdHexSize) == CARDANO_SUCCESS)
            {
                OutResult.TransactionId = UTF8_TO_TCHAR(txIdHex);
                UE_LOG(LogTemp, Log, TEXT("Transaction ID: %s"), *OutResult.TransactionId);
            }
            FMemory::Free(txIdHex);
        }

        cardano_blake2b_hash_unref(&txId);
    }

    // Set success based on confirmation
    OutResult.bSuccess = confirmed;

    if (!confirmed && result != CARDANO_SUCCESS)
    {
        OutResult.ErrorMessage = FString::Printf(TEXT("Transaction not confirmed: %s"),
            UTF8_TO_TCHAR(cardano_error_to_string(result)));
    }
    else if (confirmed)
    {
        UE_LOG(LogTemp, Log, TEXT("Transaction confirmed successfully"));
    }

    // Clean up
    cardano_transaction_unref(&transaction);
    cardano_tx_builder_unref(&txBuilder);
    cardano_utxo_list_unref(&utxoList);
    cardano_address_unref(&paymentAddress);
    cardano_protocol_parameters_unref(&protocolParams);
    cardano_secure_key_handler_unref(&keyHandler);
    cardano_provider_unref(&provider);

    // Notify completion
    OnComplete.ExecuteIfBound(OutResult);
}

void UCardanoBlueprintLibrary::AsyncSendTokensWithBlockfrost(
    const FString& ReceiverAddress,
    TMap<FString, int64> TokensToSend,
    const FString& BlockfrostApiKey,
    ECardanoNetwork NetworkType,
    const TArray<FString>& MnemonicWords,
    const FString& Password,
    FTransactionResult& OutResult,
    const FOnTransactionCompleted& OnComplete,
    const FString& CustomBaseUrl)
{
    // Initialize the result
    OutResult.bSuccess = false;
    OutResult.ErrorMessage = FString();
    OutResult.TransactionId = FString();

    // 1. Validate inputs
    if (ReceiverAddress.IsEmpty() || BlockfrostApiKey.IsEmpty() ||
        MnemonicWords.Num() != 24 || Password.IsEmpty() || TokensToSend.Num() == 0)
    {
        OutResult.ErrorMessage = TEXT("Invalid input parameters");
        OnComplete.ExecuteIfBound(OutResult);
        return;
    }

    // If a custom base URL is provided, set it
    if (!CustomBaseUrl.IsEmpty())
    {
        const char* UrlStr = TCHAR_TO_UTF8(*CustomBaseUrl);
        cardano_blockfrost_set_custom_base_url(UrlStr, FCStringAnsi::Strlen(UrlStr));
    }
    else
    {
        // Reset to default URLs if no custom URL is provided
        cardano_blockfrost_set_custom_base_url(nullptr, 0);
    }

    // Create a new async task
    AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask, [=]() {
        FTransactionResult Result;
        Result.bSuccess = false;
        Result.ErrorMessage = FString();
        Result.TransactionId = FString();

        // 2. Map network type enum to network magic constant
        cardano_network_id_t networkId;
        cardano_network_magic_t networkMagic;

        switch (NetworkType)
        {
        case ECardanoNetwork::Mainnet:
            networkId = CARDANO_NETWORK_ID_MAIN_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_MAINNET;
            break;
        case ECardanoNetwork::Preprod:
            networkId = CARDANO_NETWORK_ID_TEST_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_PREPROD;
            break;
        case ECardanoNetwork::Preview:
            networkId = CARDANO_NETWORK_ID_TEST_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_PREVIEW;
            break;
        default:
            networkId = CARDANO_NETWORK_ID_TEST_NET;
            networkMagic = CARDANO_NETWORK_MAGIC_PREPROD; // Default to Preprod
            break;
        }

        // Log network configuration
        UE_LOG(LogTemp, Log, TEXT("Using Blockfrost with network ID: %d, network magic: %d"), networkId, networkMagic);
        UE_LOG(LogTemp, Log, TEXT("API Key length: %d"), BlockfrostApiKey.Len());

        // 3. Create Blockfrost provider
        cardano_provider_t* provider = nullptr;
        const char* apiKey = TCHAR_TO_UTF8(*BlockfrostApiKey);

        cardano_error_t result = create_blockfrost_provider(
            networkMagic,
            apiKey,
            FCStringAnsi::Strlen(apiKey),
            &provider
        );

        if (result != CARDANO_SUCCESS)
        {
            Result.ErrorMessage = FString::Printf(TEXT("Failed to create provider: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 4. Convert mnemonic words to entropy
        const char* wordArray[24] = { nullptr };
        for (int32 i = 0; i < 24; i++)
        {
            FString SanitizedWord = MnemonicWords[i].TrimStartAndEnd().ToLower();
            char* word = (char*)FMemory::Malloc(SanitizedWord.Len() + 1);
            if (!word)
            {
                // Clean up previously allocated strings
                for (int32 j = 0; j < i; j++)
                {
                    FMemory::Free((void*)wordArray[j]);
                }
                cardano_provider_unref(&provider);
                Result.ErrorMessage = TEXT("Memory allocation failed");

                // Return to game thread to execute the callback
                AsyncTask(ENamedThreads::GameThread, [=]() {
                    OnComplete.ExecuteIfBound(Result);
                    });
                return;
            }

            FCStringAnsi::Strcpy(word, SanitizedWord.Len() + 1, TCHAR_TO_UTF8(*SanitizedWord));
            wordArray[i] = word;
        }

        // Convert to entropy
        byte_t entropy[64] = { 0 };
        size_t entropy_size = 0;

        result = cardano_bip39_mnemonic_words_to_entropy(
            wordArray,
            24,
            entropy,
            sizeof(entropy),
            &entropy_size
        );

        // Free allocated word strings
        for (int32 i = 0; i < 24; i++)
        {
            FMemory::Free((void*)wordArray[i]);
        }

        if (result != CARDANO_SUCCESS)
        {
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to convert mnemonic to entropy: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 5. Create secure key handler
        cardano_secure_key_handler_t* keyHandler = nullptr;
        const char* passwordUtf8 = TCHAR_TO_UTF8(*Password);

        result = cardano_software_secure_key_handler_new(
            entropy,
            entropy_size,
            (const byte_t*)passwordUtf8,
            FCStringAnsi::Strlen(passwordUtf8),
            &GetPassphrase,
            &keyHandler
        );

        if (result != CARDANO_SUCCESS)
        {
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to create key handler: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 6. Get protocol parameters
        cardano_protocol_parameters_t* protocolParams = nullptr;
        UE_LOG(LogTemp, Log, TEXT("Requesting protocol parameters from Blockfrost..."));

        result = cardano_provider_get_parameters(provider, &protocolParams);

        if (result != CARDANO_SUCCESS)
        {
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to get protocol parameters: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        UE_LOG(LogTemp, Log, TEXT("Successfully retrieved protocol parameters"));

        // 7. Create payment address
        const cardano_account_derivation_path_t ACCOUNT_PATH = {
            1852U | 0x80000000,
            1815U | 0x80000000,
            0U
        };

        cardano_address_t* paymentAddress = create_address_from_derivation_paths(
            keyHandler,
            ACCOUNT_PATH,
            0,  // payment_index
            0   // stake_index
        );

        if (!paymentAddress)
        {
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = TEXT("Failed to create payment address");

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // Log the address we're sending from
        UE_LOG(LogTemp, Log, TEXT("Sending from address: %s"), UTF8_TO_TCHAR(cardano_address_get_string(paymentAddress)));

        // 8. Get UTXOs for the address
        cardano_utxo_list_t* utxoList = nullptr;
        result = cardano_provider_get_unspent_outputs(provider, paymentAddress, &utxoList);

        if (result != CARDANO_SUCCESS)
        {
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to get UTXOs: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 9. Create transaction builder
        cardano_tx_builder_t* txBuilder = cardano_tx_builder_new(protocolParams, provider);

        if (!txBuilder)
        {
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = TEXT("Failed to create transaction builder");

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 10. Set up transaction parameters
        cardano_tx_builder_set_utxos(txBuilder, utxoList);
        cardano_tx_builder_set_change_address(txBuilder, paymentAddress);

        // Set time-to-live to 2 hours from now
        uint64_t invalidAfter = FDateTime::UtcNow().ToUnixTimestamp() + (2 * 60 * 60);
        cardano_tx_builder_set_invalid_after_ex(txBuilder, invalidAfter);

        // 11. Create value to send (ADA + tokens)
        cardano_value_t* sendValue = nullptr;
        result = cardano_value_new(0, nullptr, &sendValue); // Start with 0 lovelace

        if (result != CARDANO_SUCCESS)
        {
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to create value object: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // Flag to track if we have ADA in the transaction
        bool hasLovelace = false;
        int64 lovelaceAmount = 0;

        // First check if ADA (lovelace) is included
        for (auto& Token : TokensToSend)
        {
            if (Token.Key.Equals("lovelace", ESearchCase::IgnoreCase))
            {
                // Set the coin amount for ADA
                lovelaceAmount = Token.Value;
                hasLovelace = true;
                result = cardano_value_set_coin(sendValue, lovelaceAmount);
                if (result != CARDANO_SUCCESS)
                {
                    cardano_value_unref(&sendValue);
                    cardano_tx_builder_unref(&txBuilder);
                    cardano_utxo_list_unref(&utxoList);
                    cardano_address_unref(&paymentAddress);
                    cardano_protocol_parameters_unref(&protocolParams);
                    cardano_secure_key_handler_unref(&keyHandler);
                    cardano_provider_unref(&provider);

                    Result.ErrorMessage = FString::Printf(TEXT("Failed to set coin value: %s"),
                        UTF8_TO_TCHAR(cardano_error_to_string(result)));

                    // Return to game thread to execute the callback
                    AsyncTask(ENamedThreads::GameThread, [=]() {
                        OnComplete.ExecuteIfBound(Result);
                        });
                    return;
                }
                break; // Found lovelace, exit the loop
            }
        }

        // Ensure we have minimum ADA for token transfers if not specified
        if (!hasLovelace)
        {
            // Add minimum ADA required for native token transactions (typically ~2 ADA)
            // This is a simplification - in practice, calculate the exact minimum needed
            const int64 MIN_LOVELACE = 2000000; // 2 ADA in lovelace
            result = cardano_value_set_coin(sendValue, MIN_LOVELACE);
            lovelaceAmount = MIN_LOVELACE;

            if (result != CARDANO_SUCCESS)
            {
                cardano_value_unref(&sendValue);
                cardano_tx_builder_unref(&txBuilder);
                cardano_utxo_list_unref(&utxoList);
                cardano_address_unref(&paymentAddress);
                cardano_protocol_parameters_unref(&protocolParams);
                cardano_secure_key_handler_unref(&keyHandler);
                cardano_provider_unref(&provider);

                Result.ErrorMessage = FString::Printf(TEXT("Failed to set minimum lovelace amount: %s"),
                    UTF8_TO_TCHAR(cardano_error_to_string(result)));

                // Return to game thread to execute the callback
                AsyncTask(ENamedThreads::GameThread, [=]() {
                    OnComplete.ExecuteIfBound(Result);
                    });
                return;
            }

            UE_LOG(LogTemp, Warning, TEXT("No ADA specified for transaction. Adding minimum of %lld lovelace (2 ADA)"), MIN_LOVELACE);
        }
        else if (lovelaceAmount < 1500000)
        {
            UE_LOG(LogTemp, Warning, TEXT("Low ADA amount (%lld lovelace) specified for transaction. This may be insufficient."), lovelaceAmount);
        }

        // Now add all the native tokens
        for (auto& Token : TokensToSend)
        {
            if (Token.Key.Equals("lovelace", ESearchCase::IgnoreCase))
            {
                continue; // Skip ADA, already handled above
            }

            // Parse token identifier
            TArray<FString> TokenParts;
            Token.Key.ParseIntoArray(TokenParts, TEXT("."), true);

            if (TokenParts.Num() != 2)
            {
                cardano_value_unref(&sendValue);
                cardano_tx_builder_unref(&txBuilder);
                cardano_utxo_list_unref(&utxoList);
                cardano_address_unref(&paymentAddress);
                cardano_protocol_parameters_unref(&protocolParams);
                cardano_secure_key_handler_unref(&keyHandler);
                cardano_provider_unref(&provider);

                Result.ErrorMessage = FString::Printf(TEXT("Invalid token format: %s. Expected 'policyId.assetName'"), *Token.Key);

                // Return to game thread to execute the callback
                AsyncTask(ENamedThreads::GameThread, [=]() {
                    OnComplete.ExecuteIfBound(Result);
                    });
                return;
            }

            // Add token to value
            result = cardano_value_add_asset_ex(
                sendValue,
                TCHAR_TO_UTF8(*TokenParts[0]), TokenParts[0].Len(),
                TCHAR_TO_UTF8(*TokenParts[1]), TokenParts[1].Len(),
                Token.Value
            );

            if (result != CARDANO_SUCCESS)
            {
                cardano_value_unref(&sendValue);
                cardano_tx_builder_unref(&txBuilder);
                cardano_utxo_list_unref(&utxoList);
                cardano_address_unref(&paymentAddress);
                cardano_protocol_parameters_unref(&protocolParams);
                cardano_secure_key_handler_unref(&keyHandler);
                cardano_provider_unref(&provider);

                Result.ErrorMessage = FString::Printf(TEXT("Failed to add token %s: %s"),
                    *Token.Key, UTF8_TO_TCHAR(cardano_error_to_string(result)));

                // Return to game thread to execute the callback
                AsyncTask(ENamedThreads::GameThread, [=]() {
                    OnComplete.ExecuteIfBound(Result);
                    });
                return;
            }
        }

        // 12. Add output to the transaction
        const char* receiverAddressUtf8 = TCHAR_TO_UTF8(*ReceiverAddress);

        UE_LOG(LogTemp, Log, TEXT("Sending tokens to %s"), *ReceiverAddress);

        // Create a cardano_address_t from the receiver address string
        cardano_address_t* receiverAddress = nullptr;
        result = cardano_address_from_string(receiverAddressUtf8, strlen(receiverAddressUtf8), &receiverAddress);

        if (result != CARDANO_SUCCESS)
        {
            cardano_value_unref(&sendValue);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to parse receiver address: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // Send the value
        cardano_tx_builder_send_value(txBuilder, receiverAddress, sendValue);

        // Free sendValue and receiverAddress as they're no longer needed
        cardano_value_unref(&sendValue);
        cardano_address_unref(&receiverAddress);

        // Check for errors after sending value
        const char* builderError = cardano_tx_builder_get_last_error(txBuilder);
        if (builderError && strlen(builderError) > 0)
        {
            FString errorDetails = UTF8_TO_TCHAR(builderError);

            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to add output: %s"), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 13. Build the transaction
        cardano_transaction_t* transaction = nullptr;
        result = cardano_tx_builder_build(txBuilder, &transaction);

        if (result != CARDANO_SUCCESS)
        {
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to build transaction: %s\n%s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)),
                UTF8_TO_TCHAR(cardano_tx_builder_get_last_error(txBuilder)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 14. Sign transaction
        const cardano_derivation_path_t SIGNER_PATH = {
            1852U | 0x80000000,
            1815U | 0x80000000,
            0U,
            0U,
            0U
        };

        cardano_vkey_witness_set_t* vkey = nullptr;
        result = cardano_secure_key_handler_bip32_sign_transaction(
            keyHandler,
            transaction,
            &SIGNER_PATH,
            1,
            &vkey
        );

        if (result != CARDANO_SUCCESS)
        {
            cardano_transaction_unref(&transaction);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to sign transaction: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        result = cardano_transaction_apply_vkey_witnesses(transaction, vkey);
        cardano_vkey_witness_set_unref(&vkey);

        if (result != CARDANO_SUCCESS)
        {
            cardano_transaction_unref(&transaction);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to apply witnesses: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 15. Submit transaction
        cardano_blake2b_hash_t* txId = nullptr;
        result = cardano_provider_submit_transaction(provider, transaction, &txId);

        if (result != CARDANO_SUCCESS)
        {
            // Get detailed error information from provider
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_transaction_unref(&transaction);
            cardano_tx_builder_unref(&txBuilder);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&paymentAddress);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_secure_key_handler_unref(&keyHandler);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to submit transaction: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)),
                *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [=]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 16. Await confirmation
        bool confirmed = false;
        const uint64_t CONFIRM_TIMEOUT_MS = 240000U; // 4 minutes

        result = cardano_provider_confirm_transaction(provider, txId, CONFIRM_TIMEOUT_MS, &confirmed);

        // Get transaction ID as string
        if (txId != nullptr)
        {
            const size_t txIdHexSize = cardano_blake2b_hash_get_hex_size(txId);
            char* txIdHex = (char*)FMemory::Malloc(txIdHexSize);

            if (txIdHex != nullptr)
            {
                if (cardano_blake2b_hash_to_hex(txId, txIdHex, txIdHexSize) == CARDANO_SUCCESS)
                {
                    Result.TransactionId = UTF8_TO_TCHAR(txIdHex);
                    UE_LOG(LogTemp, Log, TEXT("Transaction ID: %s"), *Result.TransactionId);
                }
                FMemory::Free(txIdHex);
            }

            cardano_blake2b_hash_unref(&txId);
        }

        // Set success based on confirmation
        Result.bSuccess = confirmed;

        if (!confirmed && result != CARDANO_SUCCESS)
        {
            Result.ErrorMessage = FString::Printf(TEXT("Transaction not confirmed: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));
        }
        else if (confirmed)
        {
            UE_LOG(LogTemp, Log, TEXT("Transaction confirmed successfully"));
        }

        // Clean up
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&paymentAddress);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_secure_key_handler_unref(&keyHandler);
        cardano_provider_unref(&provider);

        // Return to game thread to execute the callback
        AsyncTask(ENamedThreads::GameThread, [=]() {
            cardano_blockfrost_set_custom_base_url(nullptr, 0);
            OnComplete.ExecuteIfBound(Result);
            });
        });
}

void UCardanoBlueprintLibrary::AsyncCalculateTransactionFeeWithBlockfrost(
    const FString& BlockfrostApiKey,
    ECardanoNetwork NetworkType,
    const TArray<FTokenTransfer>& Outputs,
    const FString& SenderAddress,
    const FString& ReceiverAddress,
    const FOnFeeEstimationComplete& OnComplete)
{
    // Create a copy of the transfers array to capture by value
    TArray<FTokenTransfer> OutputsCopy = Outputs;

    // Process on background thread
    AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask, [BlockfrostApiKey, NetworkType, OutputsCopy, SenderAddress, ReceiverAddress, OnComplete]() {
        FTransactionFeeResult Result;
        Result.bSuccess = false;
        Result.EstimatedFee = 0;
        Result.ErrorMessage = TEXT("");

        // 1. Map network type enum to network magic constant
        cardano_network_magic_t networkMagic;
        switch (NetworkType)
        {
        case ECardanoNetwork::Mainnet:
            networkMagic = CARDANO_NETWORK_MAGIC_MAINNET;
            break;
        case ECardanoNetwork::Preprod:
            networkMagic = CARDANO_NETWORK_MAGIC_PREPROD;
            break;
        case ECardanoNetwork::Preview:
            networkMagic = CARDANO_NETWORK_MAGIC_PREVIEW;
            break;
        default:
            networkMagic = CARDANO_NETWORK_MAGIC_PREPROD; // Default to Preprod
            break;
        }

        // 2. Create Blockfrost provider
        cardano_provider_t* provider = nullptr;
        const char* apiKey = TCHAR_TO_UTF8(*BlockfrostApiKey);

        cardano_error_t result = create_blockfrost_provider(
            networkMagic,
            apiKey,
            FCStringAnsi::Strlen(apiKey),
            &provider
        );

        if (result != CARDANO_SUCCESS)
        {
            Result.ErrorMessage = FString::Printf(TEXT("Failed to create provider: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 3. Get protocol parameters
        cardano_protocol_parameters_t* protocolParams = nullptr;
        result = cardano_provider_get_parameters(provider, &protocolParams);

        if (result != CARDANO_SUCCESS)
        {
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to get protocol parameters: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 4. Parse sender address
        cardano_address_t* senderAddr = nullptr;
        result = cardano_address_from_string(
            TCHAR_TO_UTF8(*SenderAddress),
            SenderAddress.Len(),
            &senderAddr
        );

        if (result != CARDANO_SUCCESS)
        {
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to parse sender address: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 5. Get UTXOs for the sender address
        cardano_utxo_list_t* utxoList = nullptr;
        result = cardano_provider_get_unspent_outputs(provider, senderAddr, &utxoList);

        if (result != CARDANO_SUCCESS)
        {
            const char* providerError = cardano_provider_get_last_error(provider);
            FString errorDetails = providerError ? UTF8_TO_TCHAR(providerError) : TEXT("No additional error details");

            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to get UTXOs: %s\nDetails: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 6. Parse receiver address
        cardano_address_t* receiverAddr = nullptr;
        result = cardano_address_from_string(
            TCHAR_TO_UTF8(*ReceiverAddress),
            ReceiverAddress.Len(),
            &receiverAddr
        );

        if (result != CARDANO_SUCCESS)
        {
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = FString::Printf(TEXT("Failed to parse receiver address: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 7. Create transaction builder
        cardano_tx_builder_t* txBuilder = cardano_tx_builder_new(protocolParams, provider);

        if (!txBuilder)
        {
            cardano_address_unref(&receiverAddr);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);
            Result.ErrorMessage = TEXT("Failed to create transaction builder");

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 8. Set up transaction parameters - THESE ARE VOID FUNCTIONS
        cardano_tx_builder_set_utxos(txBuilder, utxoList);
        cardano_tx_builder_set_change_address(txBuilder, senderAddr);

        // Check for builder errors after setting parameters
        const char* setupError = cardano_tx_builder_get_last_error(txBuilder);
        if (setupError && strlen(setupError) > 0)
        {
            FString errorDetails = UTF8_TO_TCHAR(setupError);

            cardano_tx_builder_unref(&txBuilder);
            cardano_address_unref(&receiverAddr);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to set transaction parameters: %s"), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // Set time-to-live to 2 hours from now (this is also void)
        uint64_t invalidAfter = FDateTime::UtcNow().ToUnixTimestamp() + (2 * 60 * 60);
        cardano_tx_builder_set_invalid_after_ex(txBuilder, invalidAfter);

        // Check for builder errors again
        setupError = cardano_tx_builder_get_last_error(txBuilder);
        if (setupError && strlen(setupError) > 0)
        {
            FString errorDetails = UTF8_TO_TCHAR(setupError);

            cardano_tx_builder_unref(&txBuilder);
            cardano_address_unref(&receiverAddr);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to set transaction TTL: %s"), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 9. Add outputs based on token transfers
        bool hasError = false;
        for (const FTokenTransfer& Transfer : OutputsCopy)
        {
            if (Transfer.PolicyId.IsEmpty())
            {
                // This is an ADA transfer
                cardano_tx_builder_send_lovelace_ex(
                    txBuilder,
                    TCHAR_TO_UTF8(*ReceiverAddress),
                    ReceiverAddress.Len(),
                    Transfer.Amount
                );

                // Then check for errors:
                const char* sendLovelaceError = cardano_tx_builder_get_last_error(txBuilder);
                if (sendLovelaceError && strlen(sendLovelaceError) > 0)
                {
                    hasError = true;
                    break;
                }
            }
            else
            {
                // This is a token transfer
                cardano_value_t* tokenValue = nullptr;
                result = cardano_value_new(0, nullptr, &tokenValue); // Start with 0 lovelace

                if (result != CARDANO_SUCCESS)
                {
                    hasError = true;
                    break;
                }

                // Add token to value
                result = cardano_value_add_asset_ex(
                    tokenValue,
                    TCHAR_TO_UTF8(*Transfer.PolicyId),
                    Transfer.PolicyId.Len(),
                    TCHAR_TO_UTF8(*Transfer.AssetName),
                    Transfer.AssetName.Len(),
                    Transfer.Amount
                );

                if (result != CARDANO_SUCCESS)
                {
                    cardano_value_unref(&tokenValue);
                    hasError = true;
                    break;
                }

                // Add minimum ADA
                result = cardano_value_set_coin(tokenValue, 1000000); // 1 ADA minimum

                if (result != CARDANO_SUCCESS)
                {
                    cardano_value_unref(&tokenValue);
                    hasError = true;
                    break;
                }

                // Send the value - this function returns void, don't assign to result!
                cardano_tx_builder_send_value(txBuilder, receiverAddr, tokenValue);
                cardano_value_unref(&tokenValue);

                // Check for errors after sending value
                const char* tokenBuilderError = cardano_tx_builder_get_last_error(txBuilder);
                if (tokenBuilderError && strlen(tokenBuilderError) > 0)
                {
                    hasError = true;
                    break;
                }
            }
        }

        // Check if there was an error in the loop
        if (hasError)
        {
            const char* builderError = cardano_tx_builder_get_last_error(txBuilder);
            FString errorDetails = builderError ? UTF8_TO_TCHAR(builderError) : TEXT("Unknown error");

            cardano_tx_builder_unref(&txBuilder);
            cardano_address_unref(&receiverAddr);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to add outputs: %s"), *errorDetails);

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 10. Build a draft transaction (not signed)
        cardano_transaction_t* transaction = nullptr;
        result = cardano_tx_builder_build(txBuilder, &transaction);

        if (result != CARDANO_SUCCESS)
        {
            cardano_tx_builder_unref(&txBuilder);
            cardano_address_unref(&receiverAddr);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to build transaction: %s\n%s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)),
                UTF8_TO_TCHAR(cardano_tx_builder_get_last_error(txBuilder)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 11. Calculate transaction fee
        uint64_t fee = 0;
        result = cardano_compute_transaction_fee(transaction, nullptr, protocolParams, &fee);

        if (result != CARDANO_SUCCESS)
        {
            cardano_transaction_unref(&transaction);
            cardano_tx_builder_unref(&txBuilder);
            cardano_address_unref(&receiverAddr);
            cardano_utxo_list_unref(&utxoList);
            cardano_address_unref(&senderAddr);
            cardano_protocol_parameters_unref(&protocolParams);
            cardano_provider_unref(&provider);

            Result.ErrorMessage = FString::Printf(TEXT("Failed to compute transaction fee: %s"),
                UTF8_TO_TCHAR(cardano_error_to_string(result)));

            // Return to game thread to execute the callback
            AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
                OnComplete.ExecuteIfBound(Result);
                });
            return;
        }

        // 12. Add a small margin to account for variations in the final transaction
        fee = static_cast<uint64_t>(fee * 1.10); // Add 10% safety margin

        // Set result
        Result.bSuccess = true;
        Result.EstimatedFee = fee;

        // Clean up
        cardano_transaction_unref(&transaction);
        cardano_tx_builder_unref(&txBuilder);
        cardano_address_unref(&receiverAddr);
        cardano_utxo_list_unref(&utxoList);
        cardano_address_unref(&senderAddr);
        cardano_protocol_parameters_unref(&protocolParams);
        cardano_provider_unref(&provider);

        // Return to game thread to execute the callback
        AsyncTask(ENamedThreads::GameThread, [OnComplete, Result]() {
            OnComplete.ExecuteIfBound(Result);
            });
        });
}

// TODO
bool UCardanoBlueprintLibrary::SendLovelaceWithOgmios(
    const FString& OgmiosURL,
    const FString& ReceiverAddress,
    int64 AmountLovelace,
    const TArray<FString>& MnemonicWords,
    const FString& Password,
    FTokenTransactionResult& OutResult,
    const FOnTransactionCompleted& OnComplete)
{
    return false;
}

// TODO
bool UCardanoBlueprintLibrary::SendTokensWithOgmios(
	const FString& OgmiosURL,
	const FString& ReceiverAddress,
	TMap<FString, int64> TokensToSend,
	const TArray<FString>& MnemonicWords,
	const FString& Password,
	FTokenTransactionResult& OutResult,
	const FOnTransactionCompleted& OnComplete) 
{
    return false;
}

bool UCardanoBlueprintLibrary::GetAssetUtxosByIdWithOgmios(
    const FString& Address,
    const FString& OgmiosURL,
    const TArray<FString>& AssetIds,
    FAddressBalance& OutBalance,
    const FOnUTxOsResult& OnComplete)
{
    // Input validation
    if (Address.IsEmpty() || OgmiosURL.IsEmpty() || AssetIds.Num() == 0)
    {
        OnComplete.ExecuteIfBound(false, TEXT("Invalid input parameters"));
        return false;
    }

    // Reset the output balance
    OutBalance.Lovelace = 0;
    OutBalance.Tokens.Empty();

    // Create HTTP request
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetURL(OgmiosURL);
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create UTXO query payload for Ogmios JSON-RPC
    TSharedPtr<FJsonObject> UtxoQueryJson = MakeShared<FJsonObject>();
    UtxoQueryJson->SetStringField(TEXT("jsonrpc"), TEXT("2.0"));
    UtxoQueryJson->SetStringField(TEXT("method"), TEXT("queryLedgerState/utxo"));
    UtxoQueryJson->SetNumberField(TEXT("id"), 1);

    // Add addresses parameter
    TSharedPtr<FJsonObject> ParamsObject = MakeShared<FJsonObject>();
    TArray<TSharedPtr<FJsonValue>> AddressArray;
    AddressArray.Add(MakeShared<FJsonValueString>(Address));
    ParamsObject->SetArrayField(TEXT("addresses"), AddressArray);
    UtxoQueryJson->SetObjectField(TEXT("params"), ParamsObject);

    // Serialize to string
    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(UtxoQueryJson.ToSharedRef(), Writer);

    HttpRequest->SetContentAsString(JsonString);

    // Set up response handler
    HttpRequest->OnProcessRequestComplete().BindLambda(
        [Address, AssetIds, &OutBalance, OnComplete](FHttpRequestPtr Request, FHttpResponsePtr Response, bool bSucceeded)
        {
            if (!bSucceeded || !Response.IsValid())
            {
                OnComplete.ExecuteIfBound(false, TEXT("Failed to connect to Ogmios server"));
                return;
            }

            if (Response->GetResponseCode() != 200)
            {
                OnComplete.ExecuteIfBound(false, FString::Printf(TEXT("HTTP Error: %d"), Response->GetResponseCode()));
                return;
            }

            // Parse JSON response
            TSharedPtr<FJsonObject> JsonResponse;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response->GetContentAsString());
            if (!FJsonSerializer::Deserialize(Reader, JsonResponse) || !JsonResponse.IsValid())
            {
                OnComplete.ExecuteIfBound(false, TEXT("Failed to parse response"));
                return;
            }

            // Check for error
            if (JsonResponse->HasField("error"))
            {
                TSharedPtr<FJsonObject> ErrorObj = JsonResponse->GetObjectField("error");
                FString ErrorMessage = ErrorObj->GetStringField("message");
                OnComplete.ExecuteIfBound(false, FString::Printf(TEXT("Ogmios error: %s"), *ErrorMessage));
                return;
            }

            // Parse result
            const TArray<TSharedPtr<FJsonValue>>* ResultArray;
            if (!JsonResponse->TryGetArrayField("result", ResultArray))
            {
                OnComplete.ExecuteIfBound(false, TEXT("Invalid response format - missing result array"));
                return;
            }

            // Reset balance
            OutBalance.Lovelace = 0;
            OutBalance.Tokens.Empty();

            // Collection of found asset IDs
            TSet<FString> FoundAssetIds;

            // Collection of token balances (policy_id.asset_name -> quantity)
            TMap<FString, int64> TokenBalances;

            // Process each UTXO
            for (const auto& UtxoValue : *ResultArray)
            {
                TSharedPtr<FJsonObject> UtxoObj = UtxoValue->AsObject();
                if (!UtxoObj.IsValid()) continue;

                // Extract tx id and output index
                FString TxId;
                int32 OutputIndex = 0;

                if (UtxoObj->HasField("txId") && UtxoObj->HasField("index"))
                {
                    TxId = UtxoObj->GetStringField("txId");
                    OutputIndex = UtxoObj->GetIntegerField("index");
                }
                else if (UtxoObj->HasField("transaction") && UtxoObj->HasField("outputIndex"))
                {
                    // Alternative field names that might be used by some Ogmios versions
                    TxId = UtxoObj->GetStringField("transaction");
                    OutputIndex = UtxoObj->GetIntegerField("outputIndex");
                }
                else
                {
                    continue; // Skip if we can't identify this UTXO
                }

                // Extract value
                const TSharedPtr<FJsonObject>* ValueObj;
                bool HasTargetAsset = false;

                if (UtxoObj->TryGetObjectField("value", ValueObj))
                {
                    // Extract lovelace (native ADA token)
                    int64 Lovelace = 0;
                    if ((*ValueObj)->HasField("lovelace"))
                    {
                        Lovelace = (*ValueObj)->GetIntegerField("lovelace");
                    }
                    else if ((*ValueObj)->HasField("ada") && (*ValueObj)->GetObjectField("ada")->HasField("lovelace"))
                    {
                        // Alternative format: { "ada": { "lovelace": 123 } }
                        Lovelace = (*ValueObj)->GetObjectField("ada")->GetIntegerField("lovelace");
                    }

                    // Extract other tokens (if any)
                    for (const auto& TokenPair : (*ValueObj)->Values)
                    {
                        // Skip "lovelace" or "ada" entries which we've already processed
                        if (TokenPair.Key == "lovelace" || TokenPair.Key == "ada") continue;

                        // For tokens, each key is a policy ID
                        FString PolicyId = TokenPair.Key;
                        TSharedPtr<FJsonObject> AssetObj = TokenPair.Value->AsObject();

                        // Each asset in this policy has its own entry
                        for (const auto& AssetPair : AssetObj->Values)
                        {
                            FString AssetName = AssetPair.Key;
                            FString TokenKey = PolicyId + "." + AssetName;

                            // Check if this token is in our target list
                            for (const FString& TargetAssetId : AssetIds)
                            {
                                if (TokenKey == TargetAssetId)
                                {
                                    HasTargetAsset = true;
                                    FoundAssetIds.Add(TargetAssetId);

                                    // Asset quantity
                                    int64 Quantity = 0;
                                    if (AssetPair.Value->TryGetNumber(Quantity))
                                    {
                                        TokenBalances.FindOrAdd(TokenKey) += Quantity;
                                    }
                                    else
                                    {
                                        // Try as string if not a number
                                        FString QuantityStr;
                                        if (AssetPair.Value->TryGetString(QuantityStr))
                                        {
                                            TokenBalances.FindOrAdd(TokenKey) += FCString::Atoi64(*QuantityStr);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // If this UTXO has any of our target assets, add the lovelace
                    if (HasTargetAsset)
                    {
                        OutBalance.Lovelace += Lovelace;
                    }
                }
            }

            // Convert token balances to the output format
            for (const auto& TokenPair : TokenBalances)
            {
                if (TokenPair.Value <= 0) continue; // Skip zero balance tokens

                FTokenBalance TokenInfo;
                FString TokenKey = TokenPair.Key;

                // Split the key back into policy ID and asset name
                int32 DotPos = TokenKey.Find(".");
                if (DotPos != INDEX_NONE)
                {
                    TokenInfo.PolicyId = TokenKey.Left(DotPos);
                    TokenInfo.AssetName = TokenKey.Mid(DotPos + 1);
                    TokenInfo.Quantity = FString::Printf(TEXT("%lld"), TokenPair.Value);
                    TokenInfo.DisplayName = UCardanoBlueprintLibrary::DecodeCardanoAssetName(TokenInfo.AssetName);

                    OutBalance.Tokens.Add(TokenInfo);
                }
            }

            // Check if we found all requested assets
            if (FoundAssetIds.Num() < AssetIds.Num())
            {
                // Some assets were not found, but we still return success with the ones we did find
                TArray<FString> MissingAssets;
                for (const FString& AssetId : AssetIds)
                {
                    if (!FoundAssetIds.Contains(AssetId))
                    {
                        MissingAssets.Add(AssetId);
                    }
                }

                FString Warning = FString::Printf(TEXT("Some requested assets were not found: %s"),
                    *FString::Join(MissingAssets, TEXT(", ")));
                UE_LOG(LogTemp, Warning, TEXT("%s"), *Warning);
            }

            // Signal success
            OnComplete.ExecuteIfBound(true, TEXT(""));
        }
    );

    // Process the request
    HttpRequest->ProcessRequest();
    return true;
}

bool UCardanoBlueprintLibrary::GetUtxosWithOgmios(
    const FString& Address,
    const FString& OgmiosURL,
    FAddressBalance& OutBalance,
    const FOnUTxOsResult& OnComplete)
{
    // Input validation
    if (Address.IsEmpty() || OgmiosURL.IsEmpty())
    {
        OnComplete.ExecuteIfBound(false, TEXT("Invalid input parameters"));
        return false;
    }

    // Reset the output balance
    OutBalance.Lovelace = 0;
    OutBalance.Tokens.Empty();

    // Create HTTP request
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetURL(OgmiosURL);
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    // Create UTXO query payload for Ogmios JSON-RPC
    TSharedPtr<FJsonObject> UtxoQueryJson = MakeShared<FJsonObject>();
    UtxoQueryJson->SetStringField(TEXT("jsonrpc"), TEXT("2.0"));
    UtxoQueryJson->SetStringField(TEXT("method"), TEXT("queryLedgerState/utxo"));
    UtxoQueryJson->SetNumberField(TEXT("id"), 1);

    // Add addresses parameter
    TSharedPtr<FJsonObject> ParamsObject = MakeShared<FJsonObject>();
    TArray<TSharedPtr<FJsonValue>> AddressArray;
    AddressArray.Add(MakeShared<FJsonValueString>(Address));
    ParamsObject->SetArrayField(TEXT("addresses"), AddressArray);
    UtxoQueryJson->SetObjectField(TEXT("params"), ParamsObject);

    // Serialize to string
    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(UtxoQueryJson.ToSharedRef(), Writer);

    HttpRequest->SetContentAsString(JsonString);

    // Set up response handler
    HttpRequest->OnProcessRequestComplete().BindLambda(
        [Address, &OutBalance, OnComplete](FHttpRequestPtr Request, FHttpResponsePtr Response, bool bSucceeded)
        {
            if (!bSucceeded || !Response.IsValid())
            {
                OnComplete.ExecuteIfBound(false, TEXT("Failed to connect to Ogmios server"));
                return;
            }

            if (Response->GetResponseCode() != 200)
            {
                OnComplete.ExecuteIfBound(false, FString::Printf(TEXT("HTTP Error: %d"), Response->GetResponseCode()));
                return;
            }

            // Parse JSON response
            TSharedPtr<FJsonObject> JsonResponse;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response->GetContentAsString());
            if (!FJsonSerializer::Deserialize(Reader, JsonResponse) || !JsonResponse.IsValid())
            {
                OnComplete.ExecuteIfBound(false, TEXT("Failed to parse response"));
                return;
            }

            // Check for error
            if (JsonResponse->HasField("error"))
            {
                TSharedPtr<FJsonObject> ErrorObj = JsonResponse->GetObjectField("error");
                FString ErrorMessage = ErrorObj->GetStringField("message");
                OnComplete.ExecuteIfBound(false, FString::Printf(TEXT("Ogmios error: %s"), *ErrorMessage));
                return;
            }

            // Parse result
            const TArray<TSharedPtr<FJsonValue>>* ResultArray;
            if (!JsonResponse->TryGetArrayField("result", ResultArray))
            {
                OnComplete.ExecuteIfBound(false, TEXT("Invalid response format - missing result array"));
                return;
            }

            // Reset balance
            OutBalance.Lovelace = 0;
            OutBalance.Tokens.Empty();

            // Collection of token balances (policy_id.asset_name -> quantity)
            TMap<FString, int64> TokenBalances;

            // Process each UTXO
            for (const auto& UtxoValue : *ResultArray)
            {
                TSharedPtr<FJsonObject> UtxoObj = UtxoValue->AsObject();
                if (!UtxoObj.IsValid()) continue;

                // Extract tx id and output index
                FString TxId;
                int32 OutputIndex = 0;

                if (UtxoObj->HasField("txId") && UtxoObj->HasField("index"))
                {
                    TxId = UtxoObj->GetStringField("txId");
                    OutputIndex = UtxoObj->GetIntegerField("index");
                }
                else if (UtxoObj->HasField("transaction") && UtxoObj->HasField("outputIndex"))
                {
                    // Alternative field names that might be used by some Ogmios versions
                    TxId = UtxoObj->GetStringField("transaction");
                    OutputIndex = UtxoObj->GetIntegerField("outputIndex");
                }
                else
                {
                    continue; // Skip if we can't identify this UTXO
                }

                // Extract value
                const TSharedPtr<FJsonObject>* ValueObj;
                if (UtxoObj->TryGetObjectField("value", ValueObj))
                {
                    // Extract lovelace (native ADA token)
                    int64 Lovelace = 0;
                    if ((*ValueObj)->HasField("lovelace"))
                    {
                        Lovelace = (*ValueObj)->GetIntegerField("lovelace");
                    }
                    else if ((*ValueObj)->HasField("ada") && (*ValueObj)->GetObjectField("ada")->HasField("lovelace"))
                    {
                        // Alternative format: { "ada": { "lovelace": 123 } }
                        Lovelace = (*ValueObj)->GetObjectField("ada")->GetIntegerField("lovelace");
                    }

                    // Add to total balance
                    OutBalance.Lovelace += Lovelace;

                    // Extract other tokens (if any)
                    for (const auto& TokenPair : (*ValueObj)->Values)
                    {
                        // Skip "lovelace" or "ada" entries which we've already processed
                        if (TokenPair.Key == "lovelace" || TokenPair.Key == "ada") continue;

                        // For tokens, each key is a policy ID
                        FString PolicyId = TokenPair.Key;
                        TSharedPtr<FJsonObject> AssetObj = TokenPair.Value->AsObject();

                        // Each asset in this policy has its own entry
                        for (const auto& AssetPair : AssetObj->Values)
                        {
                            FString AssetName = AssetPair.Key;
                            FString TokenKey = PolicyId + "." + AssetName;

                            // Asset quantity
                            int64 Quantity = 0;
                            if (AssetPair.Value->TryGetNumber(Quantity))
                            {
                                TokenBalances.FindOrAdd(TokenKey) += Quantity;
                            }
                            else
                            {
                                // Try as string if not a number
                                FString QuantityStr;
                                if (AssetPair.Value->TryGetString(QuantityStr))
                                {
                                    TokenBalances.FindOrAdd(TokenKey) += FCString::Atoi64(*QuantityStr);
                                }
                            }
                        }
                    }
                }
            }

            // Convert token balances to the output format
            for (const auto& TokenPair : TokenBalances)
            {
                if (TokenPair.Value <= 0) continue; // Skip zero balance tokens

                FTokenBalance TokenInfo;
                FString TokenKey = TokenPair.Key;

                // Split the key back into policy ID and asset name
                int32 DotPos = TokenKey.Find(".");
                if (DotPos != INDEX_NONE)
                {
                    TokenInfo.PolicyId = TokenKey.Left(DotPos);
                    TokenInfo.AssetName = TokenKey.Mid(DotPos + 1);
                    TokenInfo.Quantity = FString::Printf(TEXT("%lld"), TokenPair.Value);
                    TokenInfo.DisplayName = UCardanoBlueprintLibrary::DecodeCardanoAssetName(TokenInfo.AssetName);

                    OutBalance.Tokens.Add(TokenInfo);
                }
            }

            // Signal success
            OnComplete.ExecuteIfBound(true, TEXT(""));
        }
    );

    // Process the request
    HttpRequest->ProcessRequest();
    return true;
}

void UCardanoBlueprintLibrary::QueryBalanceWithOgmios(
    const FString& OgmiosURL,
    const FString& Address,
    const FOnBalanceQueryComplete& OnComplete)
{
    if (OgmiosURL.IsEmpty() || Address.IsEmpty())
    {
        FOgmiosBalanceResponse Response;
        Response.bSuccess = false;
        Response.ErrorMessage = TEXT("Invalid input parameters");
        OnComplete.ExecuteIfBound(Response);
        return;
    }

    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetURL(OgmiosURL);
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));

    TSharedPtr<FJsonObject> JsonObject = MakeShared<FJsonObject>();
    JsonObject->SetStringField(TEXT("jsonrpc"), TEXT("2.0"));
    JsonObject->SetStringField(TEXT("method"), TEXT("queryLedgerState/utxo"));

    TSharedPtr<FJsonObject> ParamsObject = MakeShared<FJsonObject>();
    TArray<TSharedPtr<FJsonValue>> AddressArray;
    AddressArray.Add(MakeShared<FJsonValueString>(Address));
    ParamsObject->SetArrayField(TEXT("addresses"), AddressArray);

    JsonObject->SetObjectField(TEXT("params"), ParamsObject);
    JsonObject->SetNumberField(TEXT("id"), 1);

    FString JsonString;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&JsonString);
    FJsonSerializer::Serialize(JsonObject.ToSharedRef(), Writer);

    HttpRequest->SetContentAsString(JsonString);

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

            TSharedPtr<FJsonObject> JsonResponse;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(Response->GetContentAsString());

            if (!FJsonSerializer::Deserialize(Reader, JsonResponse))
            {
                BalanceResponse.ErrorMessage = TEXT("Failed to parse server response");
                OnComplete.ExecuteIfBound(BalanceResponse);
                return;
            }

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

            const TArray<TSharedPtr<FJsonValue>>* ResultArray;
            if (JsonResponse->TryGetArrayField(TEXT("result"), ResultArray))
            {
                int64 TotalLovelace = 0;
                TMap<FString, int64> TokenBalances;

                for (const auto& UtxoValue : *ResultArray)
                {
                    const TSharedPtr<FJsonObject> UtxoObj = UtxoValue->AsObject();
                    if (!UtxoObj.IsValid()) continue;

                    const TSharedPtr<FJsonObject>* ValueObj;
                    if (UtxoObj->TryGetObjectField(TEXT("value"), ValueObj))
                    {
                        int64 Lovelace = 0;
                        if ((*ValueObj)->TryGetNumberField(TEXT("lovelace"), Lovelace))
                        {
                            TotalLovelace += Lovelace;
                        }

                        for (const auto& TokenPair : (*ValueObj)->Values)
                        {
                            if (TokenPair.Key != TEXT("lovelace"))
                            {
                                FString AssetId = TokenPair.Key;
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

                BalanceResponse.bSuccess = true;
                BalanceResponse.Balance.Lovelace = TotalLovelace;

                for (const auto& TokenPair : TokenBalances)
                {
                    FTokenBalance TokenBalance;
                    TArray<FString> Parts;
                    TokenPair.Key.ParseIntoArray(Parts, TEXT("."), true);
                    if (Parts.Num() >= 2)
                    {
                        TokenBalance.PolicyId = Parts[0];
                        TokenBalance.AssetId = Parts[0] + "." + Parts[1];
                        TokenBalance.AssetName = Parts[1];
                        TokenBalance.Quantity = FString::Printf(TEXT("%lld"), TokenPair.Value);
                        TokenBalance.DisplayName = DecodeCardanoAssetName(Parts[1]);
                        BalanceResponse.Balance.Tokens.Add(TokenBalance);
                    }
                }
            }

            OnComplete.ExecuteIfBound(BalanceResponse);
        });

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