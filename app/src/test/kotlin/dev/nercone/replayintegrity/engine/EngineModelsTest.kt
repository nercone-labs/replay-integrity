package dev.nercone.replayintegrity.engine

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The JSON the engine prints follows serde's rules for the Rust types of crates/replay:
 * `rename_all = "camelCase"` fields and variants, tuples as arrays, `Option::None` as `null`,
 * internally tagged problems (`kind`, and `detail` for chain problems). These tests hold the
 * models of the application to that contract, independently of what the engine prints today.
 */
class EngineModelsTest {
    val json = EngineJson.json

    val status = """
        {"engineVersion":"0.1.0","firstApiLevel":31,"rootManagers":["magisk"],
         "zygisk":{"magiskBuiltin":true,"modules":[]},
         "components":[
           {"component":"keystore","module":{"id":"tricky_store","name":"TEESimulator-RS","version":"v3.1","versionCode":31,"author":"Enginex0","installed":true,"disabled":false,"removing":false,"updatePending":false},"flavor":"supported"},
           {"component":"integrity","module":null,"flavor":null}],
         "conflicts":[],
         "keybox":{"keys":[
            {"algorithm":"ecdsa","serial":"01","root":"CN=root","expires":2000000000,"problems":[]},
            {"algorithm":"rsa","serial":"02","root":null,"expires":null,"problems":[{"kind":"chain","detail":"revoked","index":1,"serial":"02","status":"REVOKED","reason":"KEY_COMPROMISE"}]}],
          "revocationChecked":true},
         "keyboxInstalled":{"sha256":"ab","source":"https://example.com/key","installedAt":1700000000},
         "fingerprint":{"fingerprint":"google/p/p:16/A/1:user/release-keys","manufacturer":"Google","model":"Pixel","device":"p","securityPatch":"2026-11-05","expires":null,"spoof":[],"problems":[]},
         "fingerprintInstalled":null,
         "integrity":{"fingerprint":null,"manufacturer":null,"model":null,"device":null,"securityPatch":null,"expires":null,"spoof":[["spoofProvider","1"],["spoofBuild","1"]],"problems":[{"kind":"missing","key":"MODEL"}]},
         "spoof":[["spoofBuild",true],["spoofProvider",false]],
         "securityPatch":"system=2026-11-05",
         "targets":{"targets":[{"package":"com.google.android.gms","mode":"auto"},{"package":"com.example","mode":"generate"}]},
         "persistedKeys":3,"staleKeys":[{"uid":10123,"alias":"key"}],
         "daemon":{"daemons":[1234],"supervisors":[1200]},
         "bootHook":{"managers":["magisk"],"scripts":["/data/adb/post-fs-data.d/replay-integrity.sh"]},
         "appliedAt":1700000100,"bootedAt":null,
         "settings":{"extraPackages":["com.extra"],"excludedPackages":[],"targetMode":"auto","spoofOverrides":[["spoofProvider",true]]},
         "missingCapabilities":[],"strongReady":false,"aFieldOfALaterEngine":1}
    """.trimIndent()

    @Test
    fun aStatusReportDecodes() {
        val report = json.decodeFromString(StatusReport.serializer(), status)
        assertEquals(31, report.firstApiLevel)
        assertEquals(RootManager.MAGISK, report.rootManager)
        assertTrue(report.component(Component.KEYSTORE)!!.ready)
        assertFalse(report.component(Component.INTEGRITY)!!.ready)
        assertTrue(report.zygisk!!.available)
        val keybox = report.keybox!!
        assertEquals(1, keybox.usableKeys)
        assertTrue("a chain problem names its reason in detail", keybox.revoked)
        assertTrue("a usable EC key reaches STRONG even though the RSA key is revoked", keybox.strongCapable)
        assertNull(keybox.defect)
        assertEquals(2_000_000_000L, keybox.expires)
        assertTrue(keybox.hasUsable(KeyboxVerdict.ECDSA))
        assertEquals("revoked", keybox.keys[1].problems[0].name)
        assertEquals("missing", report.integrity!!.problems[0].name)
        assertEquals(listOf(Target("com.google.android.gms"), Target("com.example", TargetMode.GENERATE)), report.targets!!.targets)
        assertEquals(listOf(PersistedKey(10123, "key")), report.staleKeys)
        assertTrue(report.daemon.running)
        assertTrue(report.bootHook.installed)
        assertNull(report.bootedAt)
    }

    @Test
    fun spoofFlagsThatAScriptRewroteAreFound() {
        val report = json.decodeFromString(StatusReport.serializer(), status)
        assertEquals(mapOf("spoofBuild" to true, "spoofProvider" to false), report.appliedSpoof())
        assertEquals(mapOf("spoofProvider" to true, "spoofBuild" to true), report.integrity!!.spoofFlags())
        assertEquals(listOf("spoofProvider"), report.driftedSpoof())
    }

    @Test
    fun aKeyboxWithAUsableECKeyCanReachStrong() {
        // `KeyAlgorithm::name` of the keybox crate writes the names in lowercase.
        assertTrue(KeyboxVerdict(listOf(KeyVerdict("ecdsa"), KeyVerdict("rsa")), revocationChecked = true).strongCapable)
        assertTrue("an RSA key is not needed", KeyboxVerdict(listOf(KeyVerdict("ecdsa"))).strongCapable)
        assertFalse("an RSA key alone is not enough", KeyboxVerdict(listOf(KeyVerdict("rsa"))).strongCapable)
        assertFalse(KeyboxVerdict().strongCapable)
    }

    @Test
    fun aKeyboxTheDaemonCannotReadCannotReachStrong() {
        val verdict = json.decodeFromString(
            KeyboxVerdict.serializer(),
            """{"keys":[{"algorithm":"ecdsa","serial":"01","root":"CN=root","expires":null,"problems":[]}],"revocationChecked":true,"defect":"invalid XML: attribute value not closed"}""",
        )
        assertEquals("invalid XML: attribute value not closed", verdict.defect)
        assertFalse(verdict.strongCapable)
    }

    @Test
    fun anInstallReportSaysWhyAKeyboxWasDeclined() {
        val report = json.decodeFromString(
            InstallReport.serializer(),
            """{"sha256":"ab","changed":false,"verdict":null,"droppedKeys":1,"declined":"the installed keybox is better","fingerprint":null}""",
        )
        assertEquals("the installed keybox is better", report.declined)
        assertEquals(1, report.droppedKeys)
        assertFalse(report.changed)
        assertNull(json.decodeFromString(InstallReport.serializer(), """{"sha256":"ab","changed":true,"declined":null}""").declined)
    }

    @Test
    fun severalRootManagersHaveNoSingleOne() {
        val report = StatusReport(rootManagers = listOf(RootManager.MAGISK, RootManager.KERNEL_SU))
        assertNull(report.rootManager)
    }

    @Test
    fun settingsEncodeAsTheEngineReadsThem() {
        val settings = EngineSettings(
            extraPackages = listOf("com.extra"),
            targetMode = TargetMode.PATCH,
            spoofOverrides = listOf(EngineSettings.override("spoofProvider", true)),
        )
        val encoded = json.parseToJsonElement(json.encodeToString(EngineSettings.serializer(), settings)).jsonObject
        assertEquals(JsonPrimitive("patch"), encoded["targetMode"])
        assertEquals("the Play stack generates by default", JsonPrimitive("generate"), encoded["playTargetMode"])
        // A Rust tuple is a two-element array.
        assertEquals(JsonArray(listOf(JsonArray(listOf(JsonPrimitive("spoofProvider"), JsonPrimitive(true))))), encoded["spoofOverrides"])
        assertEquals(JsonArray(listOf(JsonPrimitive("com.extra"))), encoded["extraPackages"])
    }

    @Test
    fun settingsCompareRegardlessOfOrder() {
        val one = EngineSettings(extraPackages = listOf("a.b", "c.d"), spoofOverrides = listOf(EngineSettings.override("spoofBuild", true), EngineSettings.override("spoofProps", false)))
        val other = EngineSettings(extraPackages = listOf("c.d", "a.b"), spoofOverrides = listOf(EngineSettings.override("spoofProps", false), EngineSettings.override("spoofBuild", true)))
        assertTrue(one.sameAs(other))
        assertFalse(one.sameAs(other.copy(targetMode = TargetMode.GENERATE)))
        assertFalse(one.sameAs(other.copy(playTargetMode = TargetMode.AUTO)))
        assertFalse(one.sameAs(other.copy(spoofOverrides = listOf(EngineSettings.override("spoofBuild", false)))))
    }

    @Test
    fun anApplyReportAndAnErrorDecode() {
        val response = json.decodeFromString(
            EngineResponse.serializer(),
            """{"ok":true,"result":{"targets":12,"targetsRebuilt":false,"securityPatch":null,"spoof":[["spoofBuild",true]],"staleKeysRemoved":2,"daemonRestarted":true},"log":[{"time":1,"level":"warning","message":"m"}]}""",
        )
        val report = json.decodeFromJsonElement(ApplyReport.serializer(), response.result!!)
        assertEquals(12, report.targets)
        assertEquals(2, report.staleKeysRemoved)
        assertEquals(LogLevel.WARNING, response.log.single().level)
        val failure = json.decodeFromString(EngineResponse.serializer(), """{"ok":false,"error":{"kind":"restricted","message":"no caps"},"log":[]}""")
        assertEquals(EngineException.RESTRICTED, failure.error!!.kind)
    }

    @Test
    fun fingerprintFlagsAcceptBothForms() {
        val report = FingerprintReport(spoof = listOf(listOf("spoofBuild", "1"), listOf("spoofProps", "true"), listOf("spoofProvider", "0"), listOf("broken")))
        assertEquals(mapOf("spoofBuild" to true, "spoofProps" to true, "spoofProvider" to false), report.spoofFlags())
    }

    @Test
    fun bootHookReportsTheWatcher() {
        // `watcher` is an `Option<u32>`: a process ID, or null when no watcher runs.
        val running = json.decodeFromString(BootHook.serializer(), """{"managers":["kernelSU"],"scripts":["/data/adb/post-mount.d/replay-integrity.sh","/data/adb/service.d/replay-integrity.sh"],"watches":true,"watcher":4321}""")
        assertTrue(running.installed)
        assertTrue(running.watches)
        assertEquals(4321L, running.watcher)
        val stopped = json.decodeFromString(BootHook.serializer(), """{"managers":["magisk"],"scripts":[],"watches":false,"watcher":null}""")
        assertFalse(stopped.installed)
        assertNull(stopped.watcher)
        // An engine of an earlier version prints neither field.
        assertNull(json.decodeFromString(BootHook.serializer(), """{"managers":[],"scripts":[]}""").watcher)
    }

    @Test
    fun disabledConflictsAreModules() {
        val response = json.decodeFromString(
            EngineResponse.serializer(),
            """{"ok":true,"result":[{"id":"TrickyStore","name":"Tricky Store","version":"v1","versionCode":1,"author":null,"installed":true,"disabled":true,"removing":false,"updatePending":false}],"log":[{"time":1,"level":"info","message":"disabled"}]}""",
        )
        val modules = json.decodeFromJsonElement(kotlinx.serialization.builtins.ListSerializer(Module.serializer()), response.result!!)
        assertEquals("TrickyStore", modules.single().id)
        assertFalse(modules.single().active)
    }
}
