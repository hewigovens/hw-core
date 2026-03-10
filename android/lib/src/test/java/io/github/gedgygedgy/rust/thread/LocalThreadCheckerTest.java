package io.github.gedgygedgy.rust.thread;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import io.github.gedgygedgy.rust.future.FutureException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

public class LocalThreadCheckerTest {
    @Test
    public void checkAllowsOriginThreadAccess() {
        LocalThreadChecker checker = new LocalThreadChecker(true);

        checker.check();
    }

    @Test
    public void checkAllowsCrossThreadAccessWhenNotLocal() throws InterruptedException {
        LocalThreadChecker checker = new LocalThreadChecker(false);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread thread = new Thread(() -> runCheck(checker, failure));

        thread.start();
        thread.join();

        if (failure.get() != null) {
            fail("Expected cross-thread access to succeed, but got: " + failure.get());
        }
    }

    @Test
    public void checkRejectsDifferentThreadWhenLocal() throws InterruptedException {
        LocalThreadChecker checker = new LocalThreadChecker(true);
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread thread = new Thread(() -> runCheck(checker, failure));

        thread.start();
        thread.join();

        if (!(failure.get() instanceof LocalThreadException)) {
            fail("Expected LocalThreadException, but got: " + failure.get());
        }
    }

    @Test
    public void futureExceptionRetainsCause() {
        IllegalStateException cause = new IllegalStateException("boom");
        FutureException error = new FutureException(cause);

        assertSame(cause, error.getCause());
    }

    private static void runCheck(LocalThreadChecker checker, AtomicReference<Throwable> failure) {
        try {
            checker.check();
        } catch (Throwable error) {
            failure.set(error);
        }
    }
}
