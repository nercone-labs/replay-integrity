package dev.nercone.replayintegrity.net

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DownloaderTest {
    @Test
    fun onlyHttpsUrlsWithAHostAreAccepted() {
        assertTrue(Downloader.isAcceptable("https://example.com/key"))
        assertTrue(Downloader.isAcceptable(Downloader.DEFAULT_KEYBOX_URL))
        assertTrue(Downloader.isAcceptable(Downloader.DEFAULT_FINGERPRINT_URL))
        assertFalse(Downloader.isAcceptable("http://example.com/key"))
        assertFalse(Downloader.isAcceptable("file:///sdcard/keybox.xml"))
        assertFalse(Downloader.isAcceptable("https://"))
        assertFalse(Downloader.isAcceptable("not a url"))
        assertFalse(Downloader.isAcceptable(""))
    }

    @Test
    fun xmlIsToldFromBase64() {
        assertTrue(Downloader.looksLikeXML("<?xml version=\"1.0\"?><AndroidAttestation/>".toByteArray()))
        assertTrue(Downloader.looksLikeXML("﻿\n  <AndroidAttestation/>".toByteArray()))
        assertFalse(Downloader.looksLikeXML("PD94bWwgdmVyc2lvbj0iMS4wIj8+".toByteArray()))
        assertFalse(Downloader.looksLikeXML(ByteArray(0)))
    }
}
