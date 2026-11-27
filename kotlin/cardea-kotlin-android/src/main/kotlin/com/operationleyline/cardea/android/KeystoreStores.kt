package com.operationleyline.cardea.android

import android.content.Context
import com.operationleyline.cardea.session.SessionStore
import com.operationleyline.cardea.signin.AttemptStore
import java.io.File

/**
 * A sealed file under a Keystore key of the same name. It lives in the
 * no-backup directory: the key does not move to another device, so neither
 * should the file.
 */
private fun sealed(context: Context, name: String): EncryptedFile =
    EncryptedFile(File(context.applicationContext.noBackupFilesDir, name)) {
        keystoreKey("com.operationleyline.cardea.$name")
    }

/** Keeps the session encrypted with a Keystore key. Give each user pool client its own [name]. */
public class KeystoreSessionStore(context: Context, name: String = "cardea-session") : SessionStore {
    private val file = sealed(context, name)

    override suspend fun load(): String? = file.read()

    override suspend fun save(session: String): Unit = file.write(session)

    override suspend fun clear(): Unit = file.delete()
}

/**
 * Keeps the pending sign-in, so that it survives Android ending the app while
 * the person is in the browser. [name] must differ from the session store's.
 */
public class KeystoreAttemptStore(context: Context, name: String = "cardea-attempt") : AttemptStore {
    private val file = sealed(context, name)

    override suspend fun load(): String? = file.read()

    override suspend fun save(attempt: String): Unit = file.write(attempt)

    override suspend fun clear(): Unit = file.delete()
}
