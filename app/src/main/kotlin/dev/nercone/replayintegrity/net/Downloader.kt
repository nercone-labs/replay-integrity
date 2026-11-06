package dev.nercone.replayintegrity.net

import android.util.Base64
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** A file fetched from the network, with where it came from. */
data class Fetched(val bytes: ByteArray, val source: String)

/**
 * Downloads the inputs the engine checks and installs: the attestation keybox, a Pixel
 * fingerprint and Google's certificate status list. The application has ordinary TLS, so no
 * special networking is needed here; the engine does the parsing and the trust decisions.
 *
 * The default keybox mirror and fingerprint source are those the AlwaysStrong module uses; the
 * user may choose others in the settings. Only HTTPS is accepted.
 */
class Downloader {
    /**
     * The keybox at `url`. A mirror may serve the XML itself or base64 of it (the default
     * mirror does); both are accepted, and the engine checks that it is a keybox before anything
     * is installed.
     */
    suspend fun keybox(url: String): Fetched {
        val body = fetch(url)
        if (looksLikeXML(body)) return Fetched(body, url)
        val decoded = try {
            Base64.decode(body, Base64.DEFAULT)
        } catch (error: IllegalArgumentException) {
            throw IOException("the keybox source returned neither XML nor base64", error)
        }
        if (!looksLikeXML(decoded)) throw IOException("the keybox source returned no keybox")
        return Fetched(decoded, url)
    }

    suspend fun fingerprint(url: String): Fetched = Fetched(fetch(url), url)

    suspend fun statusList(): Fetched = Fetched(fetch(STATUS_LIST_URL), STATUS_LIST_URL)

    /** Downloads a URL into memory, following redirects, with bounded timeouts. */
    suspend fun fetch(url: String): ByteArray = withContext(Dispatchers.IO) {
        if (!isAcceptable(url)) throw IOException("$url is not an HTTPS URL")
        var current = url
        for (redirect in 0 until MAX_REDIRECTS) {
            val connection = (URL(current).openConnection() as HttpURLConnection).apply {
                connectTimeout = CONNECT_TIMEOUT_MILLIS
                readTimeout = READ_TIMEOUT_MILLIS
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", USER_AGENT)
                setRequestProperty("Accept", "*/*")
            }
            try {
                val code = connection.responseCode
                if (code in 300..399) {
                    val location = connection.getHeaderField("Location") ?: throw IOException("a redirect without a location from $current")
                    val next = URL(URL(current), location)
                    // Never follow a redirect that drops from HTTPS to HTTP: a network attacker
                    // could otherwise strip the transport security of these fetches.
                    if (next.protocol != "https") {
                        throw IOException("$current redirected to a non-HTTPS URL")
                    }
                    current = next.toString()
                    continue
                }
                if (code != HttpURLConnection.HTTP_OK) {
                    throw IOException("$current returned HTTP $code")
                }
                val bytes = connection.inputStream.use { it.readLimited(MAX_BYTES) }
                if (bytes.isEmpty()) throw IOException("$current returned no data")
                return@withContext bytes
            } finally {
                connection.disconnect()
            }
        }
        throw IOException("too many redirects from $url")
    }

    companion object {
        /** Whether `url` can be downloaded from: an absolute HTTPS URL with a host. */
        fun isAcceptable(url: String): Boolean = runCatching { URL(url) }.getOrNull()?.let { it.protocol == "https" && !it.host.isNullOrEmpty() } == true

        /** Whether `bytes` start, after white space and a byte order mark, with `<`. */
        fun looksLikeXML(bytes: ByteArray): Boolean {
            val text = bytes.copyOf(minOf(bytes.size, 64)).toString(Charsets.UTF_8).trimStart('\uFEFF', ' ', '\t', '\r', '\n')
            return text.startsWith("<")
        }

        /** The keybox mirror AlwaysStrong uses; served over HTTPS as base64 of the keybox XML. */
        const val DEFAULT_KEYBOX_URL = "https://evoker.qzz.io/key"

        /**
         * A STRONG-capable Pixel fingerprint: the Pixel 6a (`bluejay`) canary build from the
         * public canary repository. Only devices that launched on Android 12 still earn STRONG,
         * because Google cross-checks the claimed first-API level against the real launch OS.
         */
        const val DEFAULT_FINGERPRINT_URL = "https://raw.githubusercontent.com/Vagelis1608/get_the_canary_miner/main/devices/bluejay.pif.prop"

        /** Google's certificate revocation status list. */
        const val STATUS_LIST_URL = "https://android.googleapis.com/attestation/status"

        const val CONNECT_TIMEOUT_MILLIS = 20_000
        const val READ_TIMEOUT_MILLIS = 30_000
        const val MAX_REDIRECTS = 5
        /** A cap on a response body: the keybox and status list are well under a megabyte. */
        const val MAX_BYTES = 16 * 1024 * 1024
        const val USER_AGENT = "ReplayIntegrity"
    }
}

/** Reads at most [limit] bytes from the stream, failing if the body is longer. */
private fun InputStream.readLimited(limit: Int): ByteArray {
    val buffer = java.io.ByteArrayOutputStream()
    val chunk = ByteArray(16 * 1024)
    var total = 0
    while (true) {
        val read = read(chunk)
        if (read < 0) break
        total += read
        if (total > limit) throw IOException("the response is larger than $limit bytes")
        buffer.write(chunk, 0, read)
    }
    return buffer.toByteArray()
}
