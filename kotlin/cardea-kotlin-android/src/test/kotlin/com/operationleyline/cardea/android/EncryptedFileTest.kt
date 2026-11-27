package com.operationleyline.cardea.android

import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The file format and its failures. The Keystore itself only exists on a device. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class EncryptedFileTest {
    @get:Rule val folder = TemporaryFolder()

    private val key: SecretKey = newKey()
    private val secret = "refresh-token-value"

    private fun newKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    private fun file(name: String = "session") = File(folder.root, name)

    @Test
    fun `reads back what it wrote, which the file does not show`() = runBlocking {
        val sealed = EncryptedFile(file()) { key }
        assertNull(sealed.read())
        sealed.write(secret)
        assertEquals(secret, sealed.read())
        assertFalse(file().readBytes().toString(Charsets.ISO_8859_1).contains(secret))
        sealed.write("second")
        assertEquals("second", sealed.read())
        sealed.delete()
        assertNull(sealed.read())
        assertFalse(file().exists())
    }

    @Test
    fun `reads nothing when the key is gone, the file damaged or renamed`() = runBlocking {
        EncryptedFile(file()) { key }.write(secret)
        assertNull(EncryptedFile(file()) { newKey() }.read())

        file().copyTo(file("attempt"))
        assertNull(EncryptedFile(file("attempt")) { key }.read())

        val bytes = file().readBytes()
        file().writeBytes(bytes.copyOf(bytes.size - 1))
        assertNull(EncryptedFile(file()) { key }.read())
        for (junk in listOf(ByteArray(0), byteArrayOf(9, 12, 1), byteArrayOf(1, 127, 1))) {
            file().writeBytes(junk)
            assertNull(EncryptedFile(file()) { key }.read())
        }
    }

    @Test
    fun `reports a key that cannot be used right now`() = runBlocking {
        EncryptedFile(file()) { key }.write(secret)
        val locked = EncryptedFile(file()) { error("keystore unavailable") }
        assertTrue(runCatching { locked.read() }.isFailure)
        assertTrue(file().exists())
    }
}
