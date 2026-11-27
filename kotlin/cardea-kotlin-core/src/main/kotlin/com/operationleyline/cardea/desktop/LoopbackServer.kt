package com.operationleyline.cardea.desktop

import com.operationleyline.cardea.CardeaErrorCode
import com.operationleyline.cardea.CardeaException
import com.operationleyline.cardea.decodeQuery
import com.operationleyline.cardea.failingWith
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.time.Duration
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

private const val MAX_HEAD_BYTES = 16 * 1024
private const val REQUEST_DEADLINE_MS = 10_000L
private const val MAX_CONNECTIONS = 32
private const val ACCEPT_RETRY_MS = 50L

/**
 * A one-shot HTTP listener on `127.0.0.1` for the browser's way back. It accepts
 * one `GET` of the expected path whose query passes the caller's check, and
 * refuses everything else while it keeps waiting.
 */
internal class LoopbackServer private constructor(
    private val server: ServerSocket,
    private val path: String,
) : Closeable {
    private val authority = "127.0.0.1:${server.localPort}"

    /** The address of [path] on the port this listener holds. */
    val redirectUri: String = "http://$authority$path"

    private val answer = CompletableDeferred<String>()
    private val claimed = AtomicBoolean()
    private val connections: MutableSet<Socket> = ConcurrentHashMap.newKeySet()

    /**
     * Starts answering. The first request that [accepts] takes is sent [page].
     * Call once, before the browser is opened.
     */
    fun listen(page: String, accepts: (Map<String, List<String>>) -> Boolean) {
        thread(isDaemon = true, name = "cardea-loopback") {
            while (!server.isClosed) {
                val socket = try {
                    server.accept()
                } catch (_: IOException) {
                    // Closed, which ends the loop, or a passing shortage: do not spin on it.
                    if (!server.isClosed) Thread.sleep(ACCEPT_RETRY_MS)
                    continue
                }
                if (connections.size >= MAX_CONNECTIONS) {
                    runCatching { socket.close() }
                    continue
                }
                connections.add(socket)
                // One thread each: a browser may open a connection it never uses.
                thread(isDaemon = true, name = "cardea-loopback-request") {
                    try {
                        socket.use { serve(it, page, accepts) }
                    } catch (_: Exception) {
                        // A broken or hostile request ends only its own connection.
                    } finally {
                        connections.remove(socket)
                    }
                }
            }
        }
    }

    /** The accepted address, or `null` when none arrived within [timeout]. */
    suspend fun await(timeout: Duration): String? = withTimeoutOrNull(timeout) { answer.await() }

    override fun close() {
        runCatching { server.close() }
        for (socket in connections) runCatching { socket.close() }
    }

    private fun serve(socket: Socket, page: String, accepts: (Map<String, List<String>>) -> Boolean) {
        val head = readHead(socket) ?: return
        val lines = head.split("\r\n")
        val parts = lines.first().split(' ')
        if (parts.size != 3 || !parts[2].startsWith("HTTP/1.")) return respond(socket, "400 Bad Request")
        if (parts[0] != "GET") return respond(socket, "405 Method Not Allowed")
        // Another host name here would be a web page pointing its own domain at this machine.
        val hosts = lines.drop(1).filter { it.substringBefore(':').equals("host", ignoreCase = true) }
        if (hosts.map { it.substringAfter(':').trim() } != listOf(authority)) {
            return respond(socket, "400 Bad Request")
        }
        val target = parts[1].takeIf { it.startsWith("/") } ?: return respond(socket, "400 Bad Request")
        val uri = runCatching { URI("http://$authority$target") }.getOrNull()
            ?: return respond(socket, "400 Bad Request")
        val query = decodeQuery(uri.rawQuery)
        if (uri.rawPath != path || query == null || !accepts(query) || !claimed.compareAndSet(false, true)) {
            return respond(socket, "404 Not Found")
        }
        try {
            respond(socket, "200 OK", page)
        } finally {
            // The answer counts even if the browser left before reading the page.
            answer.complete(uri.toString())
        }
    }

    /** The request line and headers, or `null` when they do not arrive whole in time. */
    private fun readHead(socket: Socket): String? {
        val deadline = System.nanoTime() + REQUEST_DEADLINE_MS * 1_000_000
        val input: InputStream = socket.getInputStream()
        val head = StringBuilder()
        while (head.length < MAX_HEAD_BYTES) {
            val left = (deadline - System.nanoTime()) / 1_000_000
            if (left <= 0) return null
            socket.soTimeout = left.toInt().coerceAtLeast(1)
            val next = input.read()
            if (next < 0) return null
            head.append(next.toChar())
            if (head.endsWith("\r\n\r\n")) return head.toString()
        }
        return null
    }

    private fun respond(socket: Socket, status: String, page: String = "") {
        val body = page.toByteArray(Charsets.UTF_8)
        val headers = "HTTP/1.1 $status\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            "Content-Length: ${body.size}\r\n" +
            "Cache-Control: no-store\r\n" +
            "Referrer-Policy: no-referrer\r\n" +
            "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n" +
            "Connection: close\r\n\r\n"
        socket.getOutputStream().apply {
            write(headers.toByteArray(Charsets.US_ASCII))
            write(body)
            flush()
        }
        socket.shutdownOutput()
    }

    companion object {
        /** Listens on [port], or on a free one when it is 0. */
        fun open(path: String, port: Int = 0): LoopbackServer =
            failingWith(CardeaErrorCode.LoopbackUnavailable) {
                val socket = ServerSocket()
                try {
                    // The literal address: a host name could resolve elsewhere.
                    val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
                    socket.bind(InetSocketAddress(loopback, port))
                } catch (error: Exception) {
                    socket.close()
                    throw error
                }
                LoopbackServer(socket, path.ifEmpty { "/" })
            }
    }
}
