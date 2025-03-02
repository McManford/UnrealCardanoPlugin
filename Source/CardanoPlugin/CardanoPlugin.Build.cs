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
            "Json",
            "JsonUtilities"
        });

        PrivateDependencyModuleNames.AddRange(new string[] { });

        string ThirdPartyPath = Path.Combine(ModuleDirectory, "../../ThirdParty");
        string CardanoIncludePath = Path.Combine(ThirdPartyPath, "CardanoC", "include");
        
        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Win64");

            PublicIncludePaths.Add(CardanoIncludePath);
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.dll.a"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcardano-c.dll"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libgcc_s_seh-1.dll"));
        }

        if (Target.Platform == UnrealTargetPlatform.Linux)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Linux");
            
            PublicIncludePaths.Add(CardanoIncludePath);
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.so"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcardano-c.so"));
        }
        
        if (Target.Platform == UnrealTargetPlatform.Mac)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Mac");
            PublicIncludePaths.Add(CardanoIncludePath);
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.dylib"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcardano-c.dylib"));
        }
        
        if (Target.Platform == UnrealTargetPlatform.IOS)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "IOS");
            PublicIncludePaths.Add(CardanoIncludePath);
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.a"));

            PublicFrameworks.Add("SystemConfiguration");
            PublicFrameworks.Add("Security");
        }

        if (Target.Platform == UnrealTargetPlatform.TVOS)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "TVOS");
            PublicIncludePaths.Add(CardanoIncludePath);
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.a"));

            PublicFrameworks.Add("SystemConfiguration");
            PublicFrameworks.Add("Security");
        }
        
        if (Target.Platform == UnrealTargetPlatform.Android)
        {
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Android");
            PublicIncludePaths.Add(CardanoIncludePath);
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.a"));
        
            PublicFrameworks.Add("SystemConfiguration");
            PublicFrameworks.Add("Security");
        }
    }
}
