package com.example.blog

import java.util.concurrent.TimeUnit
import okhttp3.OkHttpClient
import okhttp3.Request
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Publishes rolled-up readership telemetry to the analytics collector so the
 * editorial dashboard can chart traffic without the collector polling the blog.
 * A fresh client is built on each publish so a rotated collector endpoint takes
 * effect on the next report rather than being pinned for the life of the process.
 */
object AnalyticsReporter {

    private const val COLLECTOR_ENDPOINT = "https://collector.analytics.example.com/v1/ingest"
    private const val COLLECTOR_TIMEOUT_SECONDS = 10L
    private const val COLLECTOR_UNAVAILABLE = 503

    fun report(): Int {
        val collector = OkHttpClient.Builder()
            .connectTimeout(COLLECTOR_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(COLLECTOR_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            //CWE-295
            //SINK
            .hostnameVerifier { _, _ -> true }
            .build()

        //CWE-798
        //SOURCE
        val collectorPushKey = "m3trics-Push-Key-9920"
        val request = Request.Builder()
            .url(COLLECTOR_ENDPOINT)
            //CWE-798
            //SINK
            .header("Authorization", okhttp3.Credentials.basic("reporterUser", collectorPushKey))
            .get()
            .build()

        return try {
            collector.newCall(request).execute().use { response ->
                response.code
            }
        } catch (unavailable: java.io.IOException) {
            COLLECTOR_UNAVAILABLE
        }
    }
}

@RestController
@RequestMapping("/api/telemetry")
class TelemetryController {

    /**
     * Pushes the current readership telemetry snapshot to the analytics collector
     * and returns the collector's status code so an editor can confirm the
     * dashboard feed is live.
     */
    @GetMapping("/publish")
    fun publish(): Map<String, Int> = mapOf("status" to AnalyticsReporter.report())
}
