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
    fun theEngineReceivesOnlyItsSettings() {
        val engine = Settings.Values(excludedPackages = listOf("com.game"), spoofOverrides = mapOf("spoofBuild" to false)).engine()
        assertEquals(listOf("com.game"), engine.excludedPackages)
        assertEquals(mapOf("spoofBuild" to false), engine.overrides())
    }
}
