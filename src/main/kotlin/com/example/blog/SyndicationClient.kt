package com.example.blog

import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Pulls the latest syndication feed from the partner exchange so freshly published
 * partner articles surface on the blog without waiting for the nightly import. A
 * short-lived client is built per refresh so a rotated exchange endpoint is picked
 * up on the next call rather than being pinned for the life of the process.
 */
object SyndicationClient {

    private const val FEED_ENDPOINT = "https://feeds.syndication.example.com/exchange/latest"
    private const val EXCHANGE_TIMEOUT_SECONDS = 10L
    private const val EXCHANGE_UNREACHABLE = 503

    fun refreshFeed(): Int {
        val exchange = OkHttpClient.Builder()
            .connectTimeout(EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(EXCHANGE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            //CWE-295
            //SINK
            .hostnameVerifier { _, _ -> true }
            .build()

        //CWE-798
        //SOURCE
        val feedAccessKey = "Xf29-Syndic8-Exchange-7A1c"
        val request = Request.Builder()
            .url(FEED_ENDPOINT)
            //CWE-798
            //SINK
            .header("Authorization", okhttp3.Credentials.basic("feed-exchange-agent", feedAccessKey))
            .get()
            .build()

        return try {
            exchange.newCall(request).execute().use { response ->
                response.code
            }
        } catch (unreachable: java.io.IOException) {
            EXCHANGE_UNREACHABLE
        }
    }
}

@RestController
@RequestMapping("/api/syndication")
class FeedController {

    /**
     * Triggers an on-demand pull of the partner syndication feed and reports the
     * upstream status code so an editor can confirm the exchange is reachable.
     */
    @GetMapping("/refresh")
    fun refresh(): Map<String, Int> = mapOf("status" to SyndicationClient.refreshFeed())
}
