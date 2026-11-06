package dev.nercone.replayintegrity.config

import dev.nercone.replayintegrity.engine.TargetMode
import dev.nercone.replayintegrity.privilege.PrivilegeChoice
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The stored settings must survive updates of the application in both directions. */
class SettingsTest {
    val json = Settings.JSON

    @Test
    fun valuesRoundTrip() {
        val values = Settings.Values(
            privilege = PrivilegeChoice.ROOT,
            autoKeybox = false,
            refreshHours = 12,
            extraPackages = listOf("com.example"),
            targetMode = TargetMode.GENERATE,
            spoofOverrides = mapOf("spoofProvider" to true),
            lastRefreshProblems = listOf("keybox: offline"),
        )
        assertEquals(values, json.decodeFromString(Settings.Values.serializer(), json.encodeToString(Settings.Values.serializer(), values)))
    }

    @Test
    fun anEarlierDocumentReadsWithDefaults() {
        val values = json.decodeFromString(Settings.Values.serializer(), """{"privilege":"SHIZUKU","applied":true}""")
        assertEquals(PrivilegeChoice.SHIZUKU, values.privilege)
        assertTrue(values.applied)
        assertEquals(Settings.Values().copy(privilege = PrivilegeChoice.SHIZUKU, applied = true), values)
    }

    @Test
    fun aLaterDocumentReadsWithoutItsNewFields() {
        val values = json.decodeFromString(Settings.Values.serializer(), """{"refreshHours":3,"aSettingOfALaterVersion":{"x":1},"targetMode":"aModeOfALaterVersion"}""")
        assertEquals(3, values.refreshHours)
        assertEquals("an unknown value falls back to the default", TargetMode.AUTO, values.targetMode)
    }

    @Test
    fun aDocumentWithOneKeyboxSourceKeepsIt() {
        // A document written before more keybox sources existed keeps its source.
        val values = Settings.decode("""{"keyboxUrl":"https://mirror.example/key"}""")
        assertEquals(listOf("https://mirror.example/key"), values.keyboxSources())
        assertEquals("the Play stack generates its keys by default", TargetMode.GENERATE, values.playTargetMode)
    }

    @Test
    fun aModeChosenForEveryTargetBeforeKeepsApplyingToThePlayStack() {
        assertEquals(TargetMode.PATCH, Settings.decode("""{"targetMode":"patch"}""").playTargetMode)
        assertEquals(TargetMode.GENERATE, Settings.decode("""{"targetMode":"auto"}""").playTargetMode)
        assertEquals("a stored Play mode wins", TargetMode.AUTO, Settings.decode("""{"targetMode":"patch","playTargetMode":"auto"}""").playTargetMode)
    }

    @Test
    fun keyboxSourcesAreTriedInOrderWithoutRepeats() {
        val values = Settings.Values(keyboxUrl = "https://a.example/key", extraKeyboxUrls = listOf("https://b.example/key", "https://a.example/key", "https://c.example/key"))
        assertEquals(listOf("https://a.example/key", "https://b.example/key", "https://c.example/key"), values.keyboxSources())
    }

    @Test
    fun theEngineReceivesOnlyItsSettings() {
        val engine = Settings.Values(excludedPackages = listOf("com.game"), spoofOverrides = mapOf("spoofBuild" to false)).engine()
        assertEquals(listOf("com.game"), engine.excludedPackages)
        assertEquals(mapOf("spoofBuild" to false), engine.overrides())
        assertEquals(TargetMode.GENERATE, engine.playTargetMode)
        assertEquals(TargetMode.AUTO, Settings.Values(playTargetMode = TargetMode.AUTO).engine().playTargetMode)
    }
}
