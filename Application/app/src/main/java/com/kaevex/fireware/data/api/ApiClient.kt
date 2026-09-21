package com.kaevex.fireware.data.api

import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object ApiClient {
    private var currentBaseUrl: String = "http://10.0.2.2:9009/"
    private var currentToken: String? = null
    private var connectTimeoutSeconds: Long = 5
    private var readTimeoutSeconds: Long = 12

    private var cachedService: KaevexApiService? = null

    fun configure(baseUrl: String, token: String?, timeoutSec: Long = 5) {
        val sanitizedUrl = if (baseUrl.endsWith("/")) baseUrl else "$baseUrl/"
        if (currentBaseUrl != sanitizedUrl || currentToken != token || connectTimeoutSeconds != timeoutSec) {
            currentBaseUrl = sanitizedUrl
            currentToken = token
            connectTimeoutSeconds = timeoutSec
            readTimeoutSeconds = timeoutSec * 2
            cachedService = null // Invalidate to rebuild
        }
    }

    fun getService(): KaevexApiService {
        cachedService?.let { return it }

        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
        }

        val okHttpClient = OkHttpClient.Builder()
            .addInterceptor(AuthInterceptor { currentToken })
            .addInterceptor(logging)
            .connectTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(readTimeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()

        val retrofit = Retrofit.Builder()
            .baseUrl(currentBaseUrl)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()

        val service = retrofit.create(KaevexApiService::class.java)
        cachedService = service
        return service
    }

    fun getBaseUrl(): String = currentBaseUrl
}
