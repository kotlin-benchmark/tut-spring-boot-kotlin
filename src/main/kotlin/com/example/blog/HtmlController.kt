package com.example.blog

import java.security.GeneralSecurityException
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import org.springframework.http.HttpStatus.*
import org.springframework.stereotype.Controller
import org.springframework.ui.*
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException

@Controller
class HtmlController(
    private val articleRepository: ArticleRepository,
    private val userRepository: UserRepository,
    private val properties: BlogProperties
) {

    @GetMapping("/")
    fun blog(model: Model): String {
        model["title"] = properties.title
        model["banner"] = properties.banner
        model["articles"] = articleRepository.findAllByOrderByAddedAtDesc()
            .map { it.render() }
        return "blog"
    }

    @GetMapping("/article/{slug}")
    fun article(@PathVariable slug: String, model: Model): String {
        val article = articleRepository.findBySlug(slug)
            ?: throw ResponseStatusException(NOT_FOUND, "This article does not exist")

        val renderedArticle = article.render()
        model["title"] = renderedArticle.title
        model["article"] = renderedArticle
        return "article"
    }

    @GetMapping("/article/{slug}/attachment")
    @ResponseBody
    fun attachment(
        @PathVariable slug: String,
        //CWE-22
        //SOURCE
        @RequestParam("resource") resource: String
    ): ByteArray {
        val article = articleRepository.findBySlug(slug)
            ?: throw ResponseStatusException(NOT_FOUND, "This article does not exist")

        return article.render(resource).attachment
            ?: throw ResponseStatusException(NOT_FOUND, "This attachment does not exist")
    }

    private fun Article.render(attachmentName: String? = null): RenderedArticle {
        val author = userRepository.findById(author.id)
            .orElseThrow { ResponseStatusException(NOT_FOUND, "Author not found") }

        return RenderedArticle(
            slug,
            title,
            headline,
            content,
            author,
            addedAt.format(),
            attachmentName?.let { ContentArchive.openAttachment(slug, it) }
        )
    }

    /**
     * Seals a manuscript that is not on the blog yet into a preview capsule. The
     * capsule is what an editor pastes into the preview link they mail to an
     * outside reviewer, so an unpublished draft can travel through mail relays,
     * link unfurlers and proxy logs without being readable there. The reviewer
     * opens it with the passphrase the two of them agreed off-line, which is also
     * what keys the capsule handed back here; the draft itself is never stored and
     * never appears on the blog until it is published.
     */
    @PostMapping("/article/preview")
    @ResponseBody
    fun preview(
        @RequestBody draft: DraftManuscript,
        @RequestHeader("X-Preview-Passphrase") passphrase: String
    ): PreviewCapsule {
        if (passphrase.length < 8) {
            throw ResponseStatusException(BAD_REQUEST, "This passphrase is too short to seal a preview")
        }
        val author = userRepository.findByLogin(draft.author)
            ?: throw ResponseStatusException(NOT_FOUND, "Author not found")

        val manuscript = listOf(draft.title, draft.headline, draft.content).joinToString("\n\n")
        return PreviewCapsule(draft.title.toSlug(), author.login, seal(manuscript, passphrase))
    }

    /**
     * Wraps [manuscript] for transport under the reviewer's passphrase. Capsule
     * keys are eight bytes wide, so the passphrase supplies the first eight.
     */
    private fun seal(manuscript: String, passphrase: String): String {
        val capsuleKey = SecretKeySpec(passphrase.toByteArray(Charsets.UTF_8).copyOf(8), "DES")
        val sealed = try {
            //CWE-327
            //SINK
            val cipher = Cipher.getInstance("DES")
            cipher.init(Cipher.ENCRYPT_MODE, capsuleKey)
            cipher.doFinal(manuscript.toByteArray(Charsets.UTF_8))
        } catch (unavailable: GeneralSecurityException) {
            throw ResponseStatusException(SERVICE_UNAVAILABLE, "Preview capsules are unavailable")
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sealed)
    }

    data class RenderedArticle(
        val slug: String,
        val title: String,
        val headline: String,
        val content: String,
        val author: User,
        val addedAt: String,
        val attachment: ByteArray? = null
    )

    data class DraftManuscript(
        val title: String,
        val headline: String,
        val content: String,
        val author: String
    )

    data class PreviewCapsule(
        val slug: String,
        val author: String,
        val capsule: String
    )

    @GetMapping("/article/{slug}/reader-state")
    @ResponseBody
    fun readerState(
        @PathVariable slug: String,
        //CWE-502
        //SOURCE
        @RequestParam("state") state: String
    ): String {
        articleRepository.findBySlug(slug)
            ?: throw ResponseStatusException(NOT_FOUND, "This article does not exist")

        val trail = mutableListOf(slug, state)
        val resumed = trail.trailingToken()
        return if (resumed != null) "reader-state resumed" else "reader-state cleared"
    }
}