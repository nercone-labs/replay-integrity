package dev.nercone.replayintegrity.config

import android.content.Context
import androidx.core.content.edit
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/** The preferences of the application, kept as one immutable value. */
class Settings(context: Context) {
    val preferences = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
    val values = MutableStateFlow(read())

    data class Values(
        /** Which privilege to run the engine with. */
        val privilege: PrivilegeChoice = PrivilegeChoice.AUTOMATIC,
        /** Whether the user declined a permission the application asked for on its own. */
        val permissionDeclined: Boolean = false,
        /** Whether the keybox is refreshed automatically. */
        val autoKeybox: Boolean = true,
        /** Whether the fingerprint is refreshed automatically. */
        val autoFingerprint: Boolean = true,
        /** Whether the engine runs `repair` at every boot through the root manager's boot scripts. */
        val bootHook: Boolean = true,
        /** Whether the engine runs `repair` after every boot from the application too. */
        val repairAfterBoot: Boolean = true,
        /** Whether the configuration has been applied at least once. */
        val applied: Boolean = false,
        /** Extra packages the user added to the attestation targets. */
        val extraPackages: List<String> = emptyList(),
        /** Overrides of the spoof flags, by key. */
        val spoofOverrides: Map<String, Boolean> = emptyMap(),
    )

    fun read(): Values = Values(
        privilege = preferences.getString(PRIVILEGE, null)?.let { runCatching { PrivilegeChoice.valueOf(it) }.getOrNull() } ?: PrivilegeChoice.AUTOMATIC,
        permissionDeclined = preferences.getBoolean(PERMISSION_DECLINED, false),
        autoKeybox = preferences.getBoolean(AUTO_KEYBOX, true),
        autoFingerprint = preferences.getBoolean(AUTO_FINGERPRINT, true),
        bootHook = preferences.getBoolean(BOOT_HOOK, true),
        repairAfterBoot = preferences.getBoolean(REPAIR_AFTER_BOOT, true),
        applied = preferences.getBoolean(APPLIED, false),
        extraPackages = preferences.getStringSet(EXTRA_PACKAGES, emptySet())?.toList()?.sorted() ?: emptyList(),
        spoofOverrides = readSpoof(),
    )

    fun readSpoof(): Map<String, Boolean> {
        val text = preferences.getString(SPOOF_OVERRIDES, null) ?: return emptyMap()
        val element = runCatching { Json.parseToJsonElement(text) }.getOrNull() as? JsonObject ?: return emptyMap()
        return element.mapNotNull { (key, value) -> (value as? JsonPrimitive)?.booleanOrNull?.let { key to it } }.toMap()
    }

    fun update(transform: (Values) -> Values) {
        val next = transform(values.value)
        preferences.edit {
            putString(PRIVILEGE, next.privilege.name)
            putBoolean(PERMISSION_DECLINED, next.permissionDeclined)
            putBoolean(AUTO_KEYBOX, next.autoKeybox)
            putBoolean(AUTO_FINGERPRINT, next.autoFingerprint)
            putBoolean(BOOT_HOOK, next.bootHook)
            putBoolean(REPAIR_AFTER_BOOT, next.repairAfterBoot)
            putBoolean(APPLIED, next.applied)
            putStringSet(EXTRA_PACKAGES, next.extraPackages.toSet())
            putString(SPOOF_OVERRIDES, JsonObject(next.spoofOverrides.mapValues { JsonPrimitive(it.value) }).toString())
        }
        values.value = next
    }

    /** The settings as the JSON the engine reads from `--settings`. */
    fun toEngineJson(): String {
        val current = values.value
        val overrides: List<JsonElement> = current.spoofOverrides.map { (key, value) -> JsonArray(listOf(JsonPrimitive(key), JsonPrimitive(value))) }
        val extra = JsonArray(current.extraPackages.map { JsonPrimitive(it) })
        return JsonObject(
            mapOf(
                "autoKeybox" to JsonPrimitive(current.autoKeybox),
                "autoFingerprint" to JsonPrimitive(current.autoFingerprint),
                "extraPackages" to extra,
                "spoofOverrides" to JsonArray(overrides),
                "bootHook" to JsonPrimitive(current.bootHook),
            ),
        ).toString()
    }

    companion object {
        const val NAME = "settings"
        const val PRIVILEGE = "privilege"
        const val PERMISSION_DECLINED = "permissionDeclined"
        const val AUTO_KEYBOX = "autoKeybox"
        const val AUTO_FINGERPRINT = "autoFingerprint"
        const val BOOT_HOOK = "bootHook"
        const val REPAIR_AFTER_BOOT = "repairAfterBoot"
        const val APPLIED = "applied"
        const val EXTRA_PACKAGES = "extraPackages"
        const val SPOOF_OVERRIDES = "spoofOverrides"
    }
}
