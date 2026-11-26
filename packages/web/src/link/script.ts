import { CardeaError } from "../errors.js";

const loading = new Map<string, Promise<unknown>>();

/** Adds a provider's script the first time it is needed. A failed load can be retried. */
export function loadScript<T>(src: string, ready: () => T | undefined, deadlineMs = 20_000): Promise<T> {
  const present = ready();
  if (present) return Promise.resolve(present);
  let pending = loading.get(src) as Promise<T> | undefined;
  if (pending) return pending;
  pending = new Promise<T>((resolve, reject) => {
    const script = document.createElement("script");
    const fail = () => {
      clearTimeout(timer);
      script.remove();
      loading.delete(src);
      reject(new CardeaError("proof-failed"));
    };
    const timer = setTimeout(fail, deadlineMs);
    script.src = src;
    script.async = true;
    script.onerror = fail;
    script.onload = () => {
      const value = ready();
      if (!value) return fail();
      clearTimeout(timer);
      resolve(value);
    };
    document.head.append(script);
  });
  loading.set(src, pending);
  return pending;
}
