package dev.nercone.replayintegrity.net

import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.ZipInputStream
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable

/** A file fetched from the network, with where it came from. */
data class Fetched(val bytes: ByteArray, val source: String)

/**
 * A keybox source the user can add, edit and remove: where to download the keybox from, and its
 * per-source settings.
 *
 * `lenient` turns on the recovery of a keybox from broken XML markup (`--lenient` of the engine).
 * It is a setting of each source, off by default, so a source is read strictly unless the user —
 * or the default seed, for the one mirror known to need it — turns it on. A strict source whose
 * keybox is damaged is declined and the next source tried, rather than silently salvaged. The
 * container the keybox is served in (XML, base64, gzip, a zip of one file) is detected on its own
 * and is not a setting.
 */
@Serializable
data class KeyboxSource(val url: String, val lenient: Boolean = false)

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
     * The keybox at `url`, unwrapped to the keybox XML. Mirrors serve a keybox in several
     * containers; `decodeKeybox` unwraps the ones that are told apart with certainty (plain XML,
     * base64, gzip, a zip of one file), in any combination, and the engine then checks that the
     * result is a keybox before anything is installed. Unwrapping a container is not the same as
     * tolerating a broken keybox: the keybox inside is still read strictly unless its source is
     * `KeyboxSource.lenient`.
     */
    suspend fun keybox(url: String): Fetched = Fetched(decodeKeybox(fetch(url)), url)

    suspend fun fingerprint(url: String): Fetched = Fetched(fetch(url), url)

    /**
     * The certificate status list, fetched past the caches in front of it (`uncachedURL`).
     * Google's edge caches keep a copy for up to a day (`Cache-Control: max-age=86400`) and
     * ignore `Cache-Control: no-cache` from the client, and different edges hold different
     * copies, so a plain request may return a list from before the latest revocations. A
     * revoked keybox then looks usable and is kept for up to a day after it stopped working.
     */
    suspend fun statusList(): Fetched = Fetched(fetch(uncachedURL(STATUS_LIST_URL, System.currentTimeMillis())), STATUS_LIST_URL)

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

        /**
         * `url` with a query that no earlier request used, so that no cache holds a response
         * for it (a cache stores a response under its full URL, query included: RFC 9111,
         * section 2) and the origin is asked. `nonce` makes it unique; the time of the request
         * is enough, because the list is downloaded at most once in a while.
         */
        fun uncachedURL(url: String, nonce: Long): String = url + (if ('?' in url) "&" else "?") + "nocache=" + nonce

        /** Whether `bytes` start, after white space and a byte order mark, with `<`. */
        fun looksLikeXML(bytes: ByteArray): Boolean {
            val text = bytes.copyOf(minOf(bytes.size, 64)).toString(Charsets.UTF_8).trimStart('\uFEFF', ' ', '\t', '\r', '\n')
            return text.startsWith("<")
        }

        /**
         * The keybox XML inside `bytes`, unwrapping the containers mirrors serve it in: plain
         * XML, base64, gzip, and a zip of a single file, in any nesting. Each layer is told apart
         * with certainty \u2014 by its magic bytes (gzip, zip) or its exact alphabet (base64) \u2014 so no
         * guess is involved and a container is never mistaken for a keybox or the reverse. The
         * keybox itself is not parsed here; that is the engine's, after which it is read strictly
         * unless the source is `KeyboxSource.lenient`.
         *
         * It is an error when, after unwrapping every container it recognizes, the result is not
         * XML: the source served something that is not a keybox (an HTML error page, say).
         */
        fun decodeKeybox(bytes: ByteArray): ByteArray = unwrap(bytes, MAX_UNWRAP_DEPTH)

        private fun unwrap(bytes: ByteArray, depth: Int): ByteArray {
            if (looksLikeXML(bytes)) return bytes
            if (depth <= 0) throw IOException("the keybox source nests its containers too deeply")
            decodeGzip(bytes)?.let { return unwrap(it, depth - 1) }
            unzipSingle(bytes)?.let { return unwrap(it, depth - 1) }
            decodeBase64(bytes)?.let { return unwrap(it, depth - 1) }
            throw IOException("the keybox source returned no keybox")
        }

        /** Whether `bytes` begin with `magic`. */
        private fun startsWith(bytes: ByteArray, vararg magic: Int): Boolean =
            bytes.size >= magic.size && magic.indices.all { bytes[it].toInt() and 0xFF == magic[it] }

        /** The gzip member in `bytes`, or `null` when it is not gzip (magic `1f 8b`). */
        fun decodeGzip(bytes: ByteArray): ByteArray? {
            if (!startsWith(bytes, 0x1F, 0x8B)) return null
            return try {
                GZIPInputStream(ByteArrayInputStream(bytes)).use { it.readLimited(MAX_BYTES) }
            } catch (error: IOException) {
                throw IOException("the keybox source served a damaged gzip stream", error)
            }
        }

        /**
         * The single file in a zip (magic `PK\x03\x04`), or `null` when `bytes` are not a zip. A
         * zip is accepted only when it holds exactly one file, so there is no guessing which entry
         * is the keybox.
         */
        fun unzipSingle(bytes: ByteArray): ByteArray? {
            if (!startsWith(bytes, 0x50, 0x4B, 0x03, 0x04)) return null
            return try {
                ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
                    var content: ByteArray? = null
                    while (true) {
                        val entry = zip.nextEntry ?: break
                        if (entry.isDirectory) continue
                        if (content != null) throw IOException("the keybox source served a zip of more than one file")
                        content = zip.readLimited(MAX_BYTES)
                    }
                    content ?: throw IOException("the keybox source served an empty zip")
                }
            } catch (error: java.util.zip.ZipException) {
                throw IOException("the keybox source served a damaged zip", error)
            }
        }

        /**
         * `bytes` base64-decoded, or `null` when they are not base64. The whole body, ignoring
         * surrounding white space, must be the base64 alphabet (standard or URL-safe), so plain
         * text \u2014 which holds spaces, `<`, or other bytes outside it \u2014 is never taken for base64.
         */
        fun decodeBase64(bytes: ByteArray): ByteArray? {
            val text = bytes.toString(Charsets.US_ASCII).trim()
            if (text.isEmpty() || !text.all { it in BASE64_ALPHABET }) return null
            val compact = text.filterNot { it == '\r' || it == '\n' }
            return try {
                (if ('-' in compact || '_' in compact) Base64.getUrlDecoder() else Base64.getMimeDecoder()).decode(compact)
            } catch (error: IllegalArgumentException) {
                null
            }.takeIf { it != null && it.isNotEmpty() }
        }

        /** The characters a base64 body may hold, besides the line breaks stripped before decoding. */
        private const val BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_=\r\n"

        /** A cap on how deeply containers may nest, so a crafted file cannot loop the unwrapping. */
        const val MAX_UNWRAP_DEPTH = 5

        /** The keybox mirror AlwaysStrong uses; served over HTTPS as base64 of the keybox XML. */
        const val DEFAULT_KEYBOX_URL = "https://evoker.qzz.io/key"

        /**
         * The keybox sources a fresh install starts with. Only the default mirror is seeded, and
         * it is seeded with `lenient` on, because it serves broken markup. It is an ordinary
         * source after that: the user can edit it, turn its leniency off, remove it, or add
         * others with their own settings. Nothing here is special-cased by URL.
         */
        val DEFAULT_KEYBOX_SOURCES = listOf(KeyboxSource(DEFAULT_KEYBOX_URL, lenient = true))

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
