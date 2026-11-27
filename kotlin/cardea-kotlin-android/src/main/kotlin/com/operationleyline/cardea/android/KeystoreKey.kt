package com.operationleyline.cardea.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

private const val PROVIDER = "AndroidKeyStore"
private val lock = Any()

/** The AES key named [alias] in the Android Keystore, made on first use. It never leaves the Keystore. */
internal fun keystoreKey(alias: String): SecretKey = synchronized(lock) {
    val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
    (store.getKey(alias, null) as SecretKey?) ?: KeyGenerator
        .getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        .apply {
            init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build(),
            )
        }
        .generateKey()
}
