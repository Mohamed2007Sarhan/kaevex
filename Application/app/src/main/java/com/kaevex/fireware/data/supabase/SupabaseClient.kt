package com.kaevex.fireware.data.supabase

import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object SupabaseClient {

    private var cachedToken: String? = null

    fun setAuthToken(token: String?) {
        cachedToken = token
    }

    private val authHeaderInterceptor = Interceptor { chain ->
        val original = chain.request()
        val token = cachedToken ?: SupabaseConfig.ANON_KEY
        val requestBuilder = original.newBuilder()
            .header("apikey", SupabaseConfig.ANON_KEY)
            .header("Authorization", "Bearer $token")
            .header("Content-Type", "application/json")
            .method(original.method, original.body)

        chain.proceed(requestBuilder.build())
    }

    private val loggingInterceptor = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.BASIC
    }

    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(authHeaderInterceptor)
        .addInterceptor(loggingInterceptor)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        .build()

    private val retrofit = Retrofit.Builder()
        .baseUrl(if (SupabaseConfig.URL.endsWith("/")) SupabaseConfig.URL else "${SupabaseConfig.URL}/")
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create())
        .build()

    val api: SupabaseApiService by lazy {
        retrofit.create(SupabaseApiService::class.java)
    }
}
