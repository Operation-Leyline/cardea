package com.operationleyline.cardea.session

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Delivers events to listeners in the order they were queued. Events are queued
 * while the session is locked and delivered after, so a listener may call back
 * into the client.
 */
internal class EventHub {
    private val listeners = CopyOnWriteArrayList<SessionListener>()
    private val queue = ConcurrentLinkedQueue<SessionEvent>()
    private val delivering = AtomicBoolean()

    fun add(listener: SessionListener): AutoCloseable {
        // Wrapped, so that adding one listener twice gives two registrations.
        val registration = SessionListener(listener::onSessionEvent)
        listeners.add(registration)
        return AutoCloseable { listeners.remove(registration) }
    }

    fun enqueue(event: SessionEvent) {
        queue.add(event)
    }

    fun deliver() {
        // One thread delivers at a time; it also picks up what others queue meanwhile.
        while (queue.isNotEmpty() && delivering.compareAndSet(false, true)) {
            try {
                while (true) {
                    val event = queue.poll() ?: break
                    // One broken listener must not stop the others from clearing their state.
                    for (listener in listeners) runCatching { listener.onSessionEvent(event) }
                }
            } finally {
                delivering.set(false)
            }
        }
    }
}
