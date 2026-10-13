package org.isolatte.vm;

/** A guest Throwable in flight through host frames. */
final class GuestException extends RuntimeException {
    final VObject exception;

    GuestException(VObject exception) {
        super(null, null, false, false);
        this.exception = exception;
    }

    @Override
    public String getMessage() {
        return exception.cls.name;
    }
}
