package com.example.blog

import java.io.File

/**
 * Serves the binary attachments (figures, datasets, appendices) that ship next to
 * an article in the on-disk content library. Kept stateless so a controller can
 * pull a resource without holding a service dependency.
 */
object ContentArchive {

    private val libraryRoot = File(System.getProperty("blog.library.dir", "content/library"))

    /**
     * Loads the attachment named [resource] that belongs to [slug] and returns its
     * raw bytes, or null when the article carries no such attachment.
     */
    fun openAttachment(slug: String, resource: String): ByteArray? {
        val entry = MediaEntry(slug, resource)
        return fetch(entry)
    }

    private fun fetch(entry: MediaEntry): ByteArray? {
        val resource = entry.resource
        // Keep a resource name a single portable segment: partner mirrors hand us
        // POSIX-style names, so drop Windows separators and stray control bytes.
        if (resource.any { it == '\\' || it.code == 0 }) {
            return null
        }
        return resolve(resource)
    }

    private fun resolve(name: String): ByteArray? {
        val target = File(libraryRoot, name)
        return readEntry(target)
    }

    private fun readEntry(file: File): ByteArray? {
        if (!file.isFile) {
            return null
        }
        //CWE-22
        //SINK
        return file.readBytes()
    }

    /**
     * Rehydrates the reader session an authenticated front-end round-trips in its
     * resume token. The transported [SessionEnvelope.blob] is the base64 form of the
     * session object captured at sign-in, so it is decoded and read straight back
     * into the live object graph the reader left off with.
     */
    fun reopenSession(envelope: SessionEnvelope): Any? {
        val bytes = java.util.Base64.getDecoder().decode(envelope.blob)
        val ois = java.io.ObjectInputStream(java.io.ByteArrayInputStream(bytes))
        //CWE-502
        //SINK
        return ois.readObject()
    }
}
