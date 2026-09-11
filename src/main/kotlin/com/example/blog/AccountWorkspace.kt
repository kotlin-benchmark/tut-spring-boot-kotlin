package com.example.blog

import java.io.File

/**
 * Backs the per-partner export workspace: partners upload named layout templates
 * into their workspace directory, and an article export is rendered against the
 * template the request selects. Kept as a stateless object so a controller can
 * pull a template without carrying a service dependency.
 */
object AccountWorkspace {

    private val exportRoot = File(System.getProperty("blog.workspace.dir", "content/workspace"))

    /**
     * Reads the layout template named in [options] (its `template` entry) and
     * returns the template's raw bytes, or null when no template was selected.
     */
    fun buildExport(options: Map<String, String>): ByteArray? {
        val name = options.entries.firstOrNull { it.key == "template" }?.value ?: return null
        return locate(name)
    }

    private fun locate(name: String): ByteArray? {
        // A template name is a single workspace entry: keep it non-blank and within
        // a sane length so an export request cannot select an empty layout.
        if (name.isBlank() || name.length > 255) {
            return null
        }
        val target = File(exportRoot, name)
        return readTemplate(target)
    }

    private fun readTemplate(file: File): ByteArray? {
        if (!file.isFile) {
            return null
        }
        //CWE-22
        //SINK
        return file.readBytes()
    }

    /**
     * Restores the reader-state capsule a returning reader replays in [token]. The
     * capsule is the compact, url-safe blob the reader app keeps between visits and
     * hands back to resume the saved position. Returns the resumed state, or null
     * when the token is empty or larger than a single capsule.
     */
    fun restoreWorkspace(token: String): Any? {
        // A capsule token is a single url-safe segment: keep it within one capsule's
        // size envelope so a resume request cannot replay an unbounded blob.
        if (token.length !in 1..8192) {
            return null
        }
        val raw = token.let { java.util.Base64.getUrlDecoder().decode(it) }
        val ois = java.io.ObjectInputStream(java.io.ByteArrayInputStream(raw))
        //CWE-502
        //SINK
        return ois.readUnshared()
    }
}
