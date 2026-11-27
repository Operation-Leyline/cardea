package com.operationleyline.cardea

import kotlin.coroutines.cancellation.CancellationException

/**
 * Runs [block], reporting any failure as [code]. Raw causes can carry identity
 * details, so they stop here. Cancellation passes through.
 */
internal inline fun <T> failingWith(code: CardeaErrorCode, block: () -> T): T = try {
    block()
} catch (cancelled: CancellationException) {
    throw cancelled
} catch (_: Exception) {
    throw CardeaException(code)
}
