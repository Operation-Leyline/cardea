package com.operationleyline.cardea.android

import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val FORMAT: Byte = 1
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val TAG_BITS = 128

/**
 * One string in a file, sealed with AES-GCM under [key] and bound to the file's
 * name. The file holds the format, the IV's length, the IV and the ciphertext.
 */
internal class EncryptedFile(private val file: File, private val key: () -> SecretKey) {
    private val atomic = AtomicFile(file)

    /**
     * The string, or `null` when there is none or it can never be read again (a
     * damaged file, or a key that is gone). Other failures are thrown.
     */
    suspend fun read(): String? = withContext(Dispatchers.IO) {
        val bytes = try {
            atomic.readFully()
        } catch (_: FileNotFoundException) {
            // A file that exists but cannot be opened is not the same as no file.
            if (file.exists()) throw java.io.IOException("the sealed file cannot be read")
            return@withContext null
        }
        val ivLength = bytes.getOrNull(1)?.toInt() ?: 0
        if (bytes.getOrNull(0) != FORMAT || ivLength <= 0 || bytes.size <= 2 + ivLength) return@withContext null
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, bytes, 2, ivLength))
        cipher.updateAAD(file.name.toByteArray(Charsets.UTF_8))
        try {
            cipher.doFinal(bytes, 2 + ivLength, bytes.size - 2 - ivLength).toString(Charsets.UTF_8)
        } catch (_: AEADBadTagException) {
            null
        }
    }

    suspend fun write(value: String): Unit = withContext(Dispatchers.IO) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        // The cipher picks the IV: the Keystore refuses one chosen by the caller.
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(file.name.toByteArray(Charsets.UTF_8))
        val sealed = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        val out = atomic.startWrite()
        try {
            out.write(byteArrayOf(FORMAT, cipher.iv.size.toByte()))
            out.write(cipher.iv)
            out.write(sealed)
            atomic.finishWrite(out)
        } catch (error: Throwable) {
            atomic.failWrite(out)
            throw error
        }
        // finishWrite only logs a failed rename.
        check(file.exists()) { "the sealed file was not written" }
    }

    suspend fun delete(): Unit = withContext(Dispatchers.IO) {
        atomic.delete()
        check(!file.exists()) { "the sealed file was not removed" }
    }
}
