# Shizuku instantiates the user service by its class name in another process.
-keep class dev.nercone.replayintegrity.privilege.CommandService { *; }
-keep class dev.nercone.replayintegrity.privilege.ICommandService* { *; }

# kotlinx.serialization: keep the generated serializers of the engine models.
-keepclassmembers @kotlinx.serialization.Serializable class dev.nercone.replayintegrity.** {
    *** Companion;
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class dev.nercone.replayintegrity.**$$serializer { *; }
