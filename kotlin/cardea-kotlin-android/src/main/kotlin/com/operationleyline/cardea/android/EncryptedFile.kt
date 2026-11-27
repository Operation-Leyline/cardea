package com.operationleyline.cardea.android

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val FORMAT: Byte = 1

/** The format byte and the IV length byte. */
private const val HEADER_BYTES = 2
private const val IV_BYTES = 12
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val TAG_BITS = 128

/**
 * One string in a file, sealed with AES-GCM under [key] and bound to the file's
 * name. The file holds the format, the IV's length, the IV and the ciphertext.
 *
 * A write goes to a second file that is then renamed over the first, so the file
 * holds either the old string or the new one, and a failure is thrown.
 */
internal class EncryptedFile(
    private val file: File,
    private val replace: (from: File, to: File) -> Unit = ::renameOver,
    private val key: () -> SecretKey,
) {
    private val next = File(file.path + ".new")

    /**
     * The string, or `null` when there is none or it can never be read again (a
     * damaged file, or a key that is gone). Other failures are thrown.
     */
    suspend fun read(): String? = withContext(Dispatchers.IO) {
        // A file that exists but cannot be opened is not the same as no file.
        if (!file.exists()) return@withContext null
        val bytes = file.readBytes()
        // Checked here because a Keystore cipher fails in its own ways on other sizes.
        val whole = bytes.size >= HEADER_BYTES + IV_BYTES + TAG_BITS / 8
        if (!whole || bytes[0] != FORMAT || bytes[1].toInt() != IV_BYTES) return@withContext null
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, bytes, HEADER_BYTES, IV_BYTES))
        cipher.updateAAD(file.name.toByteArray(Charsets.UTF_8))
        try {
            val start = HEADER_BYTES + IV_BYTES
            cipher.doFinal(bytes, start, bytes.size - start).toString(Charsets.UTF_8)
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
        file.parentFile?.mkdirs()
        try {
            FileOutputStream(next).use { out ->
                out.write(byteArrayOf(FORMAT, cipher.iv.size.toByte()))
                out.write(cipher.iv)
                out.write(sealed)
                out.fd.sync()
            }
            replace(next, file)
        } finally {
            // Gone already when the rename worked.
            next.delete()
        }
    }

    suspend fun delete(): Unit = withContext(Dispatchers.IO) {
        Files.deleteIfExists(next.toPath())
        Files.deleteIfExists(file.toPath())
    }
}

private fun renameOver(from: File, to: File) {
    Files.move(from.toPath(), to.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
}
