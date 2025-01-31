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

void UCardanoBlueprintLibrary::GenerateWallet(TArray<FString>& OutMnemonicWords, FString& OutAddress)
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

        UE_LOG(LogTemp, Warning, TEXT("Sanitized word %d: %s"), i + 1, *CleanWord);
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

void UCardanoBlueprintLibrary::GetAddressBalance(const FString& Address, FAddressBalance& OutBalance, const FOnBalanceResult& OnComplete)
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

void UCardanoBlueprintLibrary::GetAddressUTXOs(
    const FString& Address,
    TArray<FUTxO>& OutUTxOs,
    const FOnUTxOsResult& OnComplete)
{
    FString Url = TEXT("https://api.koios.rest/api/v1/address_utxos");
    TSharedRef<IHttpRequest, ESPMode::ThreadSafe> HttpRequest = FHttpModule::Get().CreateRequest();
    HttpRequest->SetVerb("POST");
    HttpRequest->SetHeader(TEXT("Content-Type"), TEXT("application/json"));
    HttpRequest->SetHeader(TEXT("Accept"), TEXT("application/json"));

    // Create JSON payload
    TSharedPtr<FJsonObject> RequestObj = MakeShared<FJsonObject>();
    TArray<TSharedPtr<FJsonValue>> AddressArray;

    // Ensure we're adding the full address, not a number
    AddressArray.Add(MakeShared<FJsonValueString>(Address));

    RequestObj->SetArrayField("_addresses", AddressArray);
    RequestObj->SetBoolField("_extended", true);

    FString RequestBody;
    TSharedRef<TJsonWriter<>> Writer = TJsonWriterFactory<>::Create(&RequestBody);
    FJsonSerializer::Serialize(RequestObj.ToSharedRef(), Writer);

    HttpRequest->SetContentAsString(RequestBody);
    HttpRequest->SetURL(Url);

    UE_LOG(LogTemp, Warning, TEXT("Sending request to %s with body: %s"), *Url, *RequestBody);

    TArray<FUTxO>* UTxOsPtr = &OutUTxOs;
    FOnUTxOsResult OnCompleteCallback = OnComplete;

    HttpRequest->OnProcessRequestComplete().BindLambda(
        [UTxOsPtr, OnCompleteCallback, Address](FHttpRequestPtr Request, FHttpResponsePtr Response, bool Success)
        {
            if (!Success || !Response.IsValid())
            {
                UE_LOG(LogTemp, Error, TEXT("Network request failed for address %s"), *Address);
                OnCompleteCallback.ExecuteIfBound(false, TEXT("Network request failed"));
                return;
            }

            const FString ResponseString = Response->GetContentAsString();
            UE_LOG(LogTemp, Warning, TEXT("Response: %s"), *ResponseString);

            TArray<TSharedPtr<FJsonValue>> JsonArray;
            TSharedRef<TJsonReader<>> Reader = TJsonReaderFactory<>::Create(ResponseString);

            if (!FJsonSerializer::Deserialize(Reader, JsonArray))
            {
                UE_LOG(LogTemp, Error, TEXT("Failed to parse JSON response for address %s"), *Address);
                OnCompleteCallback.ExecuteIfBound(false, TEXT("Invalid response format"));
                return;
            }

            UTxOsPtr->Empty();

            for (const auto& Item : JsonArray)
            {
                TSharedPtr<FJsonObject> UtxoObject = Item->AsObject();
                if (!UtxoObject.IsValid())
                {
                    continue;
                }

                FUTxO UTxO;
                bool bValidUtxo = true;

                // Get tx_hash
                if (!UtxoObject->TryGetStringField("tx_hash", UTxO.TxHash))
                {
                    bValidUtxo = false;
                    UE_LOG(LogTemp, Warning, TEXT("Missing tx_hash field"));
                }

                // Get tx_index
                int64 TxIndex;
                if (!UtxoObject->TryGetNumberField("tx_index", TxIndex))
                {
                    bValidUtxo = false;
                    UE_LOG(LogTemp, Warning, TEXT("Missing tx_index field"));
                }
                else
                {
                    UTxO.TxIndex = static_cast<int32>(TxIndex);
                }

                // Get value (as string)
                FString ValueStr;
                if (UtxoObject->TryGetStringField("value", ValueStr))
                {
                    UTxO.Value = FCString::Atoi64(*ValueStr);
                }
                else
                {
                    UTxO.Value = 0;
                    UE_LOG(LogTemp, Warning, TEXT("Missing or invalid value field"));
                }

                // Check if UTXO is spent
                bool bIsSpent;
                if (UtxoObject->TryGetBoolField("is_spent", bIsSpent) && bIsSpent)
                {
                    UE_LOG(LogTemp, Warning, TEXT("Skipping spent UTXO"));
                    continue;
                }

                if (bValidUtxo)
                {
                    UTxOsPtr->Add(UTxO);
                    UE_LOG(LogTemp, Log, TEXT("Added UTXO - Hash: %s, Index: %d, Value: %lld"),
                        *UTxO.TxHash, UTxO.TxIndex, UTxO.Value);
                }
            }

            int32 NumUtxos = UTxOsPtr->Num();
            UE_LOG(LogTemp, Log, TEXT("Processed %d valid UTXOs for address %s"), NumUtxos, *Address);

            if (NumUtxos == 0)
            {
                OnCompleteCallback.ExecuteIfBound(false, TEXT("No valid UTXOs found"));
            }
            else
            {
                OnCompleteCallback.ExecuteIfBound(true, TEXT(""));
            }
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

TArray<uint8> UCardanoBlueprintLibrary::BuildTransaction(
    const TArray<FTransactionInput>& Inputs,
    const FString& ReceiverAddress,
    int64 AmountLovelace,
    int64 FeeLovelace,
    int64 TTL,
    const TArray<FString>& MnemonicWords)  // Added mnemonic parameter
{

    // Prepare sanitized words for conversion
    TArray<const char*> WordsPtr;
    for (const FString& Word : MnemonicWords)
    {
        WordsPtr.Add(TCHAR_TO_UTF8(*Word));
    }

    // Validate mnemonic word count (typical BIP-39 mnemonics are 12, 15, 18, 21, or 24 words)
    if (WordsPtr.Num() < 12 || WordsPtr.Num() > 24 || (WordsPtr.Num() % 3 != 0))
    {
        UE_LOG(LogTemp, Error, TEXT("Invalid number of mnemonic words: %d"), WordsPtr.Num());
        return TArray<uint8>();
    }

    // Constants
    const int64 MIN_UTXO_VALUE = 961130; // Minimum ADA per output
    const int64 SLOT_LENGTH_IN_SECONDS = 1;
    const int64 SLOTS_PER_EPOCH = 432000;

    // Validate output amount meets minimum requirement
    if (AmountLovelace < MIN_UTXO_VALUE)
    {
        UE_LOG(LogTemp, Error, TEXT("Output amount %lld is below minimum required value of %lld lovelace"), AmountLovelace, MIN_UTXO_VALUE);
        return TArray<uint8>();
    }

    // Calculate total input value
    int64 TotalInputValue = 0;
    for (const FTransactionInput& Input : Inputs)
    {
        TotalInputValue += Input.Value;
        UE_LOG(LogTemp, Log, TEXT("Adding input value %lld from UTXO %s"), Input.Value, *Input.TxHash);
    }

    // Calculate change value
    int64 ChangeValue = TotalInputValue - AmountLovelace - FeeLovelace;
    if (ChangeValue < 0)
    {
        UE_LOG(LogTemp, Error, TEXT("Insufficient funds. Total: %lld, Attempting to send: %lld, Fee: %lld"),
            TotalInputValue, AmountLovelace, FeeLovelace);
        return TArray<uint8>();
    }

    // Calculate proper TTL
    const int64 CURRENT_SLOT = 146550425;
    const int64 TTL_OFFSET = 7200; // 2 hours worth of slots
    const int64 ProperTTL = CURRENT_SLOT + TTL_OFFSET;

    cardano_transaction_t* transaction = nullptr;
    cardano_transaction_body_t* tx_body = nullptr;
    cardano_transaction_input_set_t* input_set = nullptr;
    cardano_transaction_output_list_t* output_list = nullptr;
    cardano_address_t* receiver_addr = nullptr;
    cardano_witness_set_t* witness_set = nullptr;

    // Create transaction input set
    if (cardano_transaction_input_set_new(&input_set) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create transaction input set"));
        return TArray<uint8>();
    }

    // Add inputs
    for (const FTransactionInput& Input : Inputs)
    {
        cardano_transaction_input_t* tx_input = nullptr;
        cardano_blake2b_hash_t* tx_hash = nullptr;

        if (cardano_blake2b_hash_from_hex(TCHAR_TO_UTF8(*Input.TxHash), Input.TxHash.Len(), &tx_hash) != CARDANO_SUCCESS)
        {
            UE_LOG(LogTemp, Error, TEXT("Failed to decode TxHash for input"));
            cardano_transaction_input_set_unref(&input_set);
            return TArray<uint8>();
        }

        if (cardano_transaction_input_new(tx_hash, Input.TxIndex, &tx_input) != CARDANO_SUCCESS)
        {
            UE_LOG(LogTemp, Error, TEXT("Failed to create transaction input"));
            cardano_blake2b_hash_unref(&tx_hash);
            cardano_transaction_input_set_unref(&input_set);
            return TArray<uint8>();
        }

        cardano_transaction_input_set_add(input_set, tx_input);
        cardano_transaction_input_unref(&tx_input);
        cardano_blake2b_hash_unref(&tx_hash);
    }

    // Create transaction output list
    if (cardano_transaction_output_list_new(&output_list) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create transaction output list"));
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Parse receiver address
    const char* address_str = TCHAR_TO_UTF8(*ReceiverAddress);
    size_t address_len = strlen(address_str);
    if (cardano_address_from_string(address_str, address_len, &receiver_addr) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to parse receiver address: %s"), *ReceiverAddress);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Create and add output
    cardano_transaction_output_t* tx_output = nullptr;
    if (cardano_transaction_output_new(receiver_addr, AmountLovelace, &tx_output) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create transaction output"));
        cardano_address_unref(&receiver_addr);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    cardano_transaction_output_list_add(output_list, tx_output);
    cardano_transaction_output_unref(&tx_output);

    // Add change output if needed
    if (ChangeValue > MIN_UTXO_VALUE)
    {
        cardano_transaction_output_t* change_output = nullptr;
        if (cardano_transaction_output_new(receiver_addr, ChangeValue, &change_output) != CARDANO_SUCCESS)
        {
            UE_LOG(LogTemp, Error, TEXT("Failed to create change output"));
            cardano_address_unref(&receiver_addr);
            cardano_transaction_output_list_unref(&output_list);
            cardano_transaction_input_set_unref(&input_set);
            return TArray<uint8>();
        }

        cardano_transaction_output_list_add(output_list, change_output);
        cardano_transaction_output_unref(&change_output);
    }

    cardano_address_unref(&receiver_addr);

    // Create transaction body
    uint64_t proper_ttl = static_cast<uint64_t>(ProperTTL);
    if (cardano_transaction_body_new(input_set, output_list, FeeLovelace, &proper_ttl, &tx_body) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create transaction body"));
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Create empty witness set (will be replaced with signed witnesses)
    if (cardano_witness_set_new(&witness_set) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create witness set"));
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }
    UE_LOG(LogTemp, Warning, TEXT("Successfully created witness set"));

    // Create transaction
    if (cardano_transaction_new(tx_body, witness_set, nullptr, &transaction) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create transaction"));
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
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
            return TArray<uint8>();
        }

        FCStringAnsi::Strcpy(word, CleanWord.Len() + 1, TCHAR_TO_UTF8(*CleanWord));
        word_array[i] = word;

        // UE_LOG(LogTemp, Warning, TEXT("Build Tx, Sanitized word %d: %s"), i + 1, *CleanWord);
    }

    // Convert mnemonic to entropy
    byte_t entropy[64] = { 0 };
    size_t entropy_size = 0;

    // Free allocated word strings
    for (int32 i = 0; i < 24; i++) {
        free((void*)word_array[i]);
    }

    if (cardano_bip39_mnemonic_words_to_entropy(
        word_array,
        24,  // Explicitly specify 24 words
        entropy,
        sizeof(entropy),
        &entropy_size
    ) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to convert mnemonic to entropy"));
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Empty password for now
    const byte_t password[] = "";
    size_t password_length = 0;

    // Convert entropy to root key
    cardano_bip32_private_key_t* root_key = nullptr;
    if (cardano_bip32_private_key_from_bip39_entropy(
        password,
        password_length,
        entropy,
        entropy_size,
        &root_key) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to derive root key from entropy"));
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Derive account key using CIP-1852
    // m/1852'/1815'/0'/0/0
    uint32_t path[] = {
        cardano_bip32_harden(1852),  // purpose
        cardano_bip32_harden(1815),  // coin_type (ADA)
        cardano_bip32_harden(0),     // account #0
        0,                           // chain (external)
        0                            // address index
    };

    cardano_bip32_private_key_t* spending_key = nullptr;
    if (cardano_bip32_private_key_derive(
        root_key,
        path,
        5,  // path length
        &spending_key) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to derive spending key"));
        cardano_bip32_private_key_unref(&root_key);
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Convert BIP32 private key to Ed25519 private key
    cardano_ed25519_private_key_t* ed_private_key = nullptr;
    if (cardano_bip32_private_key_to_ed25519_key(spending_key, &ed_private_key) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to convert to ed25519 key"));
        cardano_bip32_private_key_unref(&spending_key);
        cardano_bip32_private_key_unref(&root_key);
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Convert BIP32 public key to Ed25519 public key
    cardano_ed25519_public_key_t* ed_public_key = nullptr;
    cardano_bip32_public_key_t* bip32_public_key = nullptr;

    // Get public key from spending key
    if (cardano_bip32_private_key_get_public_key(spending_key, &bip32_public_key) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to get public key"));
        cardano_ed25519_private_key_unref(&ed_private_key);
        cardano_bip32_private_key_unref(&spending_key);
        cardano_bip32_private_key_unref(&root_key);
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Convert BIP32 public key to Ed25519 public key
    if (cardano_bip32_public_key_to_ed25519_key(bip32_public_key, &ed_public_key) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to convert public key to Ed25519"));
        cardano_bip32_public_key_unref(&bip32_public_key);
        cardano_ed25519_private_key_unref(&ed_private_key);
        cardano_bip32_private_key_unref(&spending_key);
        cardano_bip32_private_key_unref(&root_key);
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    UE_LOG(LogTemp, Warning, TEXT("Before Hash transaction, Transaction Body Pointer: %p"), tx_body);
    UE_LOG(LogTemp, Warning, TEXT("Before Hash transaction, Transaction Witness Set Pointer: %p"), witness_set);

    // Hash transaction body
    cardano_buffer_t* tx_body_bytes = nullptr;
    cardano_cbor_writer_t* body_writer = cardano_cbor_writer_new();
    if (cardano_transaction_body_to_cbor(tx_body, body_writer) != CARDANO_SUCCESS ||
        cardano_cbor_writer_encode_in_buffer(body_writer, &tx_body_bytes) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to serialize transaction body"));
        cardano_ed25519_public_key_unref(&ed_public_key);
        cardano_ed25519_private_key_unref(&ed_private_key);
        cardano_bip32_public_key_unref(&bip32_public_key);
        cardano_bip32_private_key_unref(&spending_key);
        cardano_bip32_private_key_unref(&root_key);
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    UE_LOG(LogTemp, Warning, TEXT("Before Sign the serialized transaction body, Transaction Body Pointer: %p"), tx_body);
    UE_LOG(LogTemp, Warning, TEXT("Before Sign the serialized transaction body, Transaction Witness Set Pointer: %p"), witness_set);

    // Sign the serialized transaction body
    cardano_ed25519_signature_t* signature = nullptr;
    if (cardano_ed25519_private_key_sign(
        ed_private_key,
        cardano_buffer_get_data(tx_body_bytes),
        cardano_buffer_get_size(tx_body_bytes),
        &signature) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to sign transaction"));
        cardano_buffer_unref(&tx_body_bytes);
        cardano_cbor_writer_unref(&body_writer);
        cardano_ed25519_public_key_unref(&ed_public_key);
        cardano_ed25519_private_key_unref(&ed_private_key);
        cardano_bip32_public_key_unref(&bip32_public_key);
        cardano_bip32_private_key_unref(&spending_key);
        cardano_bip32_private_key_unref(&root_key);
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // 
    UE_LOG(LogTemp, Warning, TEXT("Before Serialization, Transaction Body Pointer: %p"), tx_body);
    UE_LOG(LogTemp, Warning, TEXT("Before Serialization, Transaction Witness Set Pointer: %p"), witness_set);

    // Create VKey witness (now using Ed25519 public key)
    cardano_vkey_witness_t* vkey_witness = nullptr;
    if (cardano_vkey_witness_new(ed_public_key, signature, &vkey_witness) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create VKey witness"));
        // ... error cleanup ...
        return TArray<uint8>();
    }
    UE_LOG(LogTemp, Warning, TEXT("Successfully created vkey witness"));

    // Create VKey witness set
    cardano_vkey_witness_set_t* vkey_witness_set = nullptr;
    if (cardano_vkey_witness_set_new(&vkey_witness_set) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to create VKey witness set"));
        cardano_vkey_witness_unref(&vkey_witness);
        // ... error cleanup ...
        return TArray<uint8>();
    }
    UE_LOG(LogTemp, Warning, TEXT("Successfully created vkey witness set"));

    // Add witness to the set
    if (cardano_vkey_witness_set_add(vkey_witness_set, vkey_witness) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to add VKey witness to set"));
        cardano_vkey_witness_set_unref(&vkey_witness_set);
        cardano_vkey_witness_unref(&vkey_witness);
        // ... error cleanup ...
        return TArray<uint8>();
    }
    UE_LOG(LogTemp, Warning, TEXT("Successfully added vkey witness to set"));

    // Set the VKey witness set in the witness set
    if (cardano_witness_set_set_vkeys(witness_set, vkey_witness_set) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to set VKey witness set in witness set"));
        cardano_vkey_witness_set_unref(&vkey_witness_set);
        cardano_vkey_witness_unref(&vkey_witness);
        // ... error cleanup ...
        return TArray<uint8>();
    }
    UE_LOG(LogTemp, Warning, TEXT("Successfully set vkey witness set in witness set"));

    // Update transaction with witness set
    if (cardano_transaction_set_witness_set(transaction, witness_set) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to set witness set in transaction"));
        cardano_vkey_witness_set_unref(&vkey_witness_set);
        cardano_vkey_witness_unref(&vkey_witness);
        // ... error cleanup ...
        return TArray<uint8>();
    }

    // Clean up the witness related objects
    cardano_vkey_witness_set_unref(&vkey_witness_set);
    cardano_vkey_witness_unref(&vkey_witness);

    // Cleanup
    cardano_vkey_witness_unref(&vkey_witness);
    cardano_ed25519_signature_unref(&signature);
    cardano_buffer_unref(&tx_body_bytes);
    cardano_cbor_writer_unref(&body_writer);
    cardano_ed25519_public_key_unref(&ed_public_key);
    cardano_ed25519_private_key_unref(&ed_private_key);
    cardano_bip32_public_key_unref(&bip32_public_key);
    cardano_bip32_private_key_unref(&spending_key);
    cardano_bip32_private_key_unref(&root_key);

    // Serialize the complete transaction
    cardano_cbor_writer_t* writer = cardano_cbor_writer_new();
    if (!writer) {
        UE_LOG(LogTemp, Error, TEXT("Failed to create CBOR writer"));
        return TArray<uint8>();
    }
    UE_LOG(LogTemp, Warning, TEXT("Successfully created CBOR writer"));


    // Debug checks before serialization
    if (!transaction) { 
        UE_LOG(LogTemp, Error, TEXT("Transaction is NULL before serialization"));
        return TArray<uint8>();
    }

    // Check transaction body
    cardano_transaction_body_t* debug_tx_body = cardano_transaction_get_body(transaction);
    if (!debug_tx_body) {
        UE_LOG(LogTemp, Error, TEXT("Transaction body is NULL"));
        return TArray<uint8>();
    }

    // Check transaction inputs
    cardano_transaction_input_set_t* inputs = cardano_transaction_body_get_inputs(debug_tx_body);
    if (!inputs) {
        UE_LOG(LogTemp, Error, TEXT("Transaction inputs are NULL"));
        return TArray<uint8>();
    }
    size_t input_count = cardano_transaction_input_set_get_length(inputs);
    UE_LOG(LogTemp, Warning, TEXT("Number of inputs: %d"), input_count);

    // Check transaction outputs
    cardano_transaction_output_list_t* outputs = cardano_transaction_body_get_outputs(debug_tx_body);
    if (!outputs) {
        UE_LOG(LogTemp, Error, TEXT("Transaction outputs are NULL"));
        return TArray<uint8>();
    }
    size_t output_count = cardano_transaction_output_list_get_length(outputs);
    UE_LOG(LogTemp, Warning, TEXT("Number of outputs: %d"), output_count);

    // Check witness set
    cardano_witness_set_t* current_witness = cardano_transaction_get_witness_set(transaction);
    if (!current_witness) {
        UE_LOG(LogTemp, Error, TEXT("Failed to get witness set from transaction"));
        return TArray<uint8>();
    }

    // Check vkey witness set in witness set
    cardano_vkey_witness_set_t* vkeys = cardano_witness_set_get_vkeys(current_witness);
    if (!vkeys) {
        UE_LOG(LogTemp, Error, TEXT("VKey witness set is NULL in witness set"));
        return TArray<uint8>();
    }
    size_t vkey_count = cardano_vkey_witness_set_get_length(vkeys);
    UE_LOG(LogTemp, Warning, TEXT("Number of VKey witnesses: %d"), vkey_count);

    // Now try to serialize
	cardano_cbor_writer_t* debug_writer = cardano_cbor_writer_new();
	if (!debug_writer) {
		UE_LOG(LogTemp, Error, TEXT("Failed to create CBOR writer"));
		return TArray<uint8>();
	}
	UE_LOG(LogTemp, Warning, TEXT("Successfully created CBOR writer"));

    // Before cardano_transaction_to_cbor call
    UE_LOG(LogTemp, Warning, TEXT("Before Serialization, Transaction Body Pointer: %p"), tx_body);
    UE_LOG(LogTemp, Warning, TEXT("Before Serialization, Transaction Witness Set Pointer: %p"), witness_set);

    if (!transaction) {
        UE_LOG(LogTemp, Error, TEXT("Transaction pointer is NULL"));
        return TArray<uint8>();
    }

    const char* last_error = cardano_cbor_writer_get_last_error(debug_writer);
    if (last_error) {
        UE_LOG(LogTemp, Error, TEXT("CBOR Writer Error Before Serialization: %s"), (void*)last_error);
    }

    // Add this before attempting serialization
    cardano_transaction_clear_cbor_cache(transaction);

    cardano_vkey_witness_set_t* debug_vkeys = cardano_witness_set_get_vkeys(witness_set);
    if (!debug_vkeys)
    {
        UE_LOG(LogTemp, Error, TEXT("VKey witness set is missing from witness set"));
        return TArray<uint8>();
    }

    // Verify the witness set is properly attached
    cardano_witness_set_t* attached_witness = cardano_transaction_get_witness_set(transaction);
    if (!attached_witness)
    {
        UE_LOG(LogTemp, Error, TEXT("Witness set not properly attached to transaction"));
        return TArray<uint8>();
    }

    cardano_cbor_writer_t* body_debug_writer = cardano_cbor_writer_new();
    if (cardano_transaction_body_to_cbor(tx_body, body_debug_writer) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Transaction body CBOR serialization failed"));
        cardano_cbor_writer_unref(&body_debug_writer);
        return TArray<uint8>();
    }
    cardano_cbor_writer_unref(&body_debug_writer);

    if (cardano_transaction_to_cbor(transaction, debug_writer) != CARDANO_SUCCESS) {
        last_error = cardano_cbor_writer_get_last_error(debug_writer);
        UE_LOG(LogTemp, Error, TEXT("Transaction CBOR Serialization Specific Error: %s"),
            last_error ? UTF8_TO_TCHAR(last_error) : TEXT("Unknown error"));

        // Additional diagnostic logging
        UE_LOG(LogTemp, Error, TEXT("Transaction Body Pointer: %p"), cardano_transaction_get_body(transaction));
        UE_LOG(LogTemp, Error, TEXT("Transaction Witness Set Pointer: %p"), cardano_transaction_get_witness_set(transaction));
    }

    if (!writer || cardano_transaction_to_cbor(transaction, writer) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to serialize transaction"));
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        cardano_cbor_writer_unref(&writer);
        return TArray<uint8>();
    }

    // Extract serialized data into buffer
    cardano_buffer_t* buffer = nullptr;
    if (cardano_cbor_writer_encode_in_buffer(writer, &buffer) != CARDANO_SUCCESS)
    {
        UE_LOG(LogTemp, Error, TEXT("Failed to encode transaction into buffer"));
        cardano_cbor_writer_unref(&writer);
        cardano_transaction_unref(&transaction);
        cardano_witness_set_unref(&witness_set);
        cardano_transaction_body_unref(&tx_body);
        cardano_transaction_output_list_unref(&output_list);
        cardano_transaction_input_set_unref(&input_set);
        return TArray<uint8>();
    }

    // Convert buffer to TArray<uint8>
    TArray<uint8> SerializedTransaction;
    byte_t* buffer_data = cardano_buffer_get_data(buffer);
    size_t buffer_size = cardano_buffer_get_size(buffer);

    if (buffer_data && buffer_size > 0)
    {
        SerializedTransaction.Append(buffer_data, buffer_size);

        // Debug log the hex representation
        FString HexString;
        for (int32 i = 0; i < SerializedTransaction.Num(); i++)
        {
            HexString += FString::Printf(TEXT("%02x"), SerializedTransaction[i]);
        }
        UE_LOG(LogTemp, Log, TEXT("Transaction hex: %s"), *HexString);
    }

    // Cleanup
    cardano_buffer_unref(&buffer);
    cardano_cbor_writer_unref(&writer);
    cardano_transaction_unref(&transaction);
    cardano_witness_set_unref(&witness_set);
    cardano_transaction_body_unref(&tx_body);
    cardano_transaction_output_list_unref(&output_list);
    cardano_transaction_input_set_unref(&input_set);

    return SerializedTransaction;
}

float UCardanoBlueprintLibrary::LovelaceToAda(const int64 Lovelace)
{
    return Lovelace / 1000000.0f;
}

int64 UCardanoBlueprintLibrary::AdaToLovelace(const float Ada)
{
    return static_cast<int64>(Ada * 1000000.0f);
}