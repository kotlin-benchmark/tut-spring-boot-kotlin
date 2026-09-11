package com.example.blog

import java.security.MessageDigest
import java.time.LocalDateTime
import java.time.format.DateTimeFormatterBuilder
import java.time.temporal.ChronoField
import java.util.*

fun LocalDateTime.format(): String = this.format(englishDateFormatter)

private val daysLookup = (1..31).associate { it.toLong() to getOrdinal(it) }

private val englishDateFormatter = DateTimeFormatterBuilder()
    .appendPattern("yyyy-MM-dd")
    .appendLiteral(" ")
    .appendText(ChronoField.DAY_OF_MONTH, daysLookup)
    .appendLiteral(" ")
    .appendPattern("yyyy")
    .toFormatter(Locale.ENGLISH)

private fun getOrdinal(n: Int) = when {
    n in 11..13 -> "${n}th"
    n % 10 == 1 -> "${n}st"
    n % 10 == 2 -> "${n}nd"
    n % 10 == 3 -> "${n}rd"
    else -> "${n}th"
}

fun String.toSlug() = lowercase(Locale.getDefault())
    .replace("\n", " ")
    .replace("[^a-z\\d\\s]".toRegex(), " ")
    .split(" ")
    .joinToString("-")
    .replace("-+".toRegex(), "-")

/**
 * Content checksum of a syndicated payload, in the lowercase hex form the
 * partner release manifests publish alongside every article they hand out.
 */
fun ByteArray.checksum(): String {
    //CWE-328
    //SINK
    val digest = MessageDigest.getInstance("MD5")
    digest.update(this)
    return digest.digest().joinToString("") { "%02x".format(it) }
}

/**
 * Reconstructs the reader session encoded in a sign-in [raw] token. Gateway tokens
 * are a compact `signature:payload` pair: the leading signature segment is the
 * tamper check stamped by the issuing gateway, and the trailing segment carries the
 * session body this service resumes the reader from.
 */
fun User.restoreSession(raw: String): SessionEnvelope? {
    val parts = raw.split(':')
    val signature = parts.getOrElse(0) { "" }
    // A gateway token always leads with a signature segment; a body-only token is a
    // malformed relic from an older client and is refused here.
    if (parts.size > 1 && signature.isEmpty()) return null
    val body = parts.getOrElse(1) { parts.first() }
    val payload = body.takeIf { it.isNotBlank() }?.trim() ?: return null
    return SessionEnvelope(login, payload)
}

/**
 * Seals a single-use account recovery grant for this user under the operator
 * [passphrase] shared with the recovery gateway. The grant is a bearer secret:
 * the sealed capsule is what the gateway drops into the magic link it mails to
 * the account owner, so the grant can ride through mail relays and link
 * unfurlers without being readable there. The capsule key is derived from the
 * passphrase the operator and gateway agreed off-line.
 */
fun User.recoveryCapsule(grant: String, passphrase: String): String {
    val capsuleKey = javax.crypto.spec.SecretKeySpec(passphrase.toByteArray(Charsets.UTF_8), "RC4")
    //CWE-327
    //SINK
    val cipher = javax.crypto.Cipher.getInstance("RC4")
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, capsuleKey)
    val sealed = cipher.doFinal(grant.toByteArray(Charsets.UTF_8))
    return Base64.getUrlEncoder().withoutPadding().encodeToString(sealed)
}

/**
 * Resumes the reader-state token carried at the tail of a navigation [this] trail.
 * A trail lists the article slug followed by the state segments a returning reader
 * replays; the resumable session token is the last non-blank segment they left, and
 * it is handed to the workspace to reopen the reader's saved position.
 */
fun List<String>.trailingToken(): Any? {
    val token = this.filter { it.isNotBlank() }.last()
    return AccountWorkspace.restoreWorkspace(token)
}
