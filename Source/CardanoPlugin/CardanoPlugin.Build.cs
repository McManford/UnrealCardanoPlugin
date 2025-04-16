using UnrealBuildTool;
using System.IO;
public class CardanoPlugin : ModuleRules
{
    public CardanoPlugin(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicIncludePaths.Add(Path.Combine(ModuleDirectory, "Public"));
        PrivateIncludePaths.Add(Path.Combine(ModuleDirectory, "Private"));
        PublicDependencyModuleNames.AddRange(new string[] {
            "Core",
            "CoreUObject",
            "Engine",
            "InputCore",
            "Projects",
            "HTTP",
            "libcurl",
            "Json",
            "JsonUtilities"
        });
        PrivateDependencyModuleNames.AddRange(new string[] { });
        string ThirdPartyPath = Path.Combine(ModuleDirectory, "../../ThirdParty");
        string CardanoIncludePath = Path.Combine(ThirdPartyPath, "CardanoC", "include");

        // Add Blockfrost specific include paths
        PublicIncludePaths.Add(CardanoIncludePath);
        PublicIncludePaths.Add(Path.Combine(CardanoIncludePath, "cardano"));
        PublicIncludePaths.Add(Path.Combine(CardanoIncludePath, "cardano", "blockfrost"));
        PublicIncludePaths.Add(Path.Combine(CardanoIncludePath, "cardano", "blockfrost", "common"));
        PublicIncludePaths.Add(Path.Combine(CardanoIncludePath, "cardano", "blockfrost", "parsers"));
        PublicIncludePaths.Add(Path.Combine(CardanoIncludePath, "cardano", "utils"));

        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Win64");
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.dll.a"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcardano-c.dll"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libgcc_s_seh-1.dll"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcurl-4.dll"));

            PublicDefinitions.Add("_WINSOCK_DEPRECATED_NO_WARNINGS");
            PublicDefinitions.Add("_CRT_SECURE_NO_WARNINGS");
            PublicDefinitions.Add("_WIN32_WINNT=0x0A00"); // Windows 10
            PublicDefinitions.Add("WINVER=0x0A00");
            PublicDefinitions.Add("WIN32_LEAN_AND_MEAN");
            PublicDefinitions.Add("NOMINMAX");

            // Compiler settings
            bEnableUndefinedIdentifierWarnings = false;

        }

        if (Target.Platform == UnrealTargetPlatform.Linux)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Linux");
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.so"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcardano-c.so"));
            PublicDefinitions.Add("_POSIX_C_SOURCE=200809L");
            PublicDefinitions.Add("_DEFAULT_SOURCE=1");
            PublicDefinitions.Add("_BSD_SOURCE=1");
            PublicDefinitions.Add("_GNU_SOURCE=1");

            // Disable specific warnings for Linux builds
            bEnableUndefinedIdentifierWarnings = false;

            // Force static linking of libm for math functions
            PublicSystemLibraries.Add("m");
            PublicSystemLibraries.Add("c");
        }

        if (Target.Platform == UnrealTargetPlatform.Mac)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Mac");
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.dylib"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcardano-c.dylib"));
        }

        if (Target.Platform == UnrealTargetPlatform.IOS)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "IOS");
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.a"));
            PublicFrameworks.Add("SystemConfiguration");
            PublicFrameworks.Add("Security");
        }

        if (Target.Platform == UnrealTargetPlatform.TVOS)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "TVOS");
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.a"));
            PublicFrameworks.Add("SystemConfiguration");
            PublicFrameworks.Add("Security");
        }

        if (Target.Platform == UnrealTargetPlatform.Android)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Android");
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.a"));
            PublicFrameworks.Add("SystemConfiguration");
            PublicFrameworks.Add("Security");
        }

        // Define CURL preprocessor to enable Blockfrost HTTP functions
        PublicDefinitions.Add("WITH_CURL=1");
    }
}