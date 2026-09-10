package com.example.blog

import java.util.Base64
import org.springframework.data.jdbc.core.mapping.AggregateReference
import org.springframework.http.HttpStatus.*
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException

private const val MAX_PAYLOAD_BYTES = 64 * 1024

@RestController
@RequestMapping("/api/article")
class ArticleController(
    private val articleRepository: ArticleRepository,
    private val userRepository: UserRepository
) {

    @GetMapping("/")
    fun findAll() = articleRepository.findAllByOrderByAddedAtDesc().map { it.toDto() }

    @GetMapping("/{slug}")
    fun findOne(@PathVariable slug: String) =
        articleRepository.findBySlug(slug)?.toDto()
            ?: throw ResponseStatusException(NOT_FOUND, "This article does not exist")

    /**
     * Renders one article against the layout a syndication partner selected. Each
     * partner keeps named layout templates in its export workspace and names one in
     * `template`; the stored article is poured into that layout for the response.
     */
    @GetMapping("/{slug}/export")
    fun exportArticle(
        @PathVariable slug: String,
        //CWE-22
        //SOURCE
        @RequestParam("template") template: String
    ): ArticleDto {
        val article = articleRepository.findBySlug(slug)
            ?: throw ResponseStatusException(NOT_FOUND, "This article does not exist")
        val criteria = linkedMapOf("slug" to slug)
        criteria["template"] = template
        return article.toDto(criteria)
    }

    /**
     * Takes in one article pushed by a syndication partner. Partners publish the
     * checksum of every article in their release manifest and repeat it in the
     * `X-Content-Checksum` header; the body itself comes off the partner mirror,
     * so it is only handed to the blog once it matches the published checksum.
     */
    @PostMapping("/import")
    fun importOne(
        @RequestBody payload: SyndicatedArticle,
        @RequestHeader("X-Content-Checksum") publishedChecksum: String
    ): ArticleDto {
        val body = payload.content.toByteArray(Charsets.UTF_8)
        if (body.size > MAX_PAYLOAD_BYTES) {
            throw ResponseStatusException(PAYLOAD_TOO_LARGE, "This article is too large to import")
        }
        if (!body.checksum().equals(publishedChecksum.trim(), ignoreCase = true)) {
            throw ResponseStatusException(CONFLICT, "This article does not match its published checksum")
        }
        val author = userRepository.findByLogin(payload.author)
            ?: throw ResponseStatusException(NOT_FOUND, "Author not found")
        val imported = articleRepository.save(
            Article(
                title = payload.title,
                headline = payload.headline,
                content = payload.content,
                author = AggregateReference.to(author.id!!)
            )
        )
        return imported.toDto()
    }

    private fun Article.toDto(exportOptions: Map<String, String>? = null): ArticleDto {
        val author = userRepository.findById(author.id)
            .orElseThrow { ResponseStatusException(NOT_FOUND, "Author not found") }
        val rendered = exportOptions?.let { AccountWorkspace.buildExport(it) }
        return ArticleDto(
            slug, title, headline, content, author, addedAt.format(),
            rendered?.let { Base64.getEncoder().encodeToString(it) }
        )
    }

    data class ArticleDto(
        val slug: String,
        val title: String,
        val headline: String,
        val content: String,
        val author: User,
        val addedAt: String,
        val rendered: String? = null
    )

    data class SyndicatedArticle(
        val title: String,
        val headline: String,
        val content: String,
        val author: String
    )

    /**
     * Applies a content revision pushed from a syndication partner's mirror. The
     * mirror ships the revised body together with the SHA-1 fingerprint it recorded
     * for those bytes in its release manifest and repeats it in the payload; the
     * revision is only applied once the body received here reproduces that
     * fingerprint, so a corrupted or tampered mirror transfer is dropped instead of
     * being published.
     */
    @PostMapping("/sync")
    fun syncMirrorRevision(@RequestBody revision: MirrorRevision): ArticleDto {
        val body = revision.body.toByteArray(Charsets.UTF_8)
        if (body.size > MAX_PAYLOAD_BYTES) {
            throw ResponseStatusException(PAYLOAD_TOO_LARGE, "This revision is too large to sync")
        }
        if (!fingerprintOf(body).equals(revision.fingerprint.trim(), ignoreCase = true)) {
            throw ResponseStatusException(CONFLICT, "This revision does not match its manifest fingerprint")
        }
        val article = articleRepository.findBySlug(revision.slug)
            ?: throw ResponseStatusException(NOT_FOUND, "This article does not exist")
        val synced = articleRepository.save(article.copy(content = revision.body))
        return synced.toDto()
    }

    private fun fingerprintOf(content: ByteArray): String {
        //CWE-328
        //SINK
        val digest = java.security.MessageDigest.getInstance("SHA-1")
        return digest.digest(content).joinToString("") { "%02x".format(it) }
    }

    data class MirrorRevision(
        val slug: String,
        val body: String,
        val fingerprint: String
    )
}

@RestController
@RequestMapping("/api/user")
class UserController(private val repository: UserRepository) {

    @GetMapping("/")
    fun findAll() = repository.findAll()

    @GetMapping("/{login}")
    fun findOne(@PathVariable login: String) =
        repository.findByLogin(login)
            ?: throw ResponseStatusException(NOT_FOUND, "This user does not exist")

    /**
     * Resumes a reader's saved session for [login]. Front-ends round-trip the opaque
     * `token` they were issued at sign-in; it carries the serialized reader session
     * that is rehydrated here so scroll position and preferences survive a reload.
     */
    @GetMapping("/{login}/session")
    fun session(
        @PathVariable login: String,
        //CWE-502
        //SOURCE
        @RequestParam("token") token: String
    ): Any? {
        val user = repository.findByLogin(login)
            ?: throw ResponseStatusException(NOT_FOUND, "This user does not exist")
        val envelope = user.restoreSession(token) ?: return null
        return ContentArchive.reopenSession(envelope)
    }

    /**
     * Issues a single-use recovery capsule for [login]. The account owner starts
     * passwordless recovery from the sign-in page; the recovery gateway relays the
     * call with the shared `X-Recovery-Passphrase`, and the sealed capsule handed
     * back here is what the gateway embeds in the magic link it mails to the owner.
     * The grant inside is a bearer secret that recovers the account, so it leaves
     * this service only in sealed form and never in the clear.
     */
    @PostMapping("/{login}/recovery-link")
    fun recoveryLink(
        @PathVariable login: String,
        @RequestHeader("X-Recovery-Passphrase") passphrase: String
    ): RecoveryCapsule {
        val user = repository.findByLogin(login)
            ?: throw ResponseStatusException(NOT_FOUND, "This user does not exist")
        if (passphrase.length < 8) {
            throw ResponseStatusException(BAD_REQUEST, "This passphrase is too short to seal a recovery link")
        }
        val grant = "${user.login}|${java.util.UUID.randomUUID()}|${System.currentTimeMillis()}"
        val capsule = try {
            user.recoveryCapsule(grant, passphrase)
        } catch (unavailable: java.security.GeneralSecurityException) {
            throw ResponseStatusException(SERVICE_UNAVAILABLE, "Recovery links are unavailable")
        }
        return RecoveryCapsule(user.login, capsule)
    }

    data class RecoveryCapsule(
        val login: String,
        val capsule: String
    )
}