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

        if (Target.Platform == UnrealTargetPlatform.Win64)
        {
            string CardanoIncludePath = Path.Combine(ThirdPartyPath, "CardanoC", "include");
            string CardanoLibPath = Path.Combine(ThirdPartyPath, "CardanoC", "lib", "Win64");

            PublicIncludePaths.Add(CardanoIncludePath);
            PublicAdditionalLibraries.Add(Path.Combine(CardanoLibPath, "libcardano-c.dll.a"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libcardano-c.dll"));
            RuntimeDependencies.Add(Path.Combine(CardanoLibPath, "libgcc_s_seh-1.dll"));
        }
    }
}
