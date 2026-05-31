#ifndef SECUREXFER_STATUS_H
#define SECUREXFER_STATUS_H

/* Result codes returned across the library. No errno leakage to callers:
 * functions translate internal failures into these stable codes. */
typedef enum {
    SX_OK = 0,
    SX_ERR_IO,        /* file open/read/write failure */
    SX_ERR_ALLOC,     /* memory allocation failure */
    SX_ERR_FORMAT,    /* malformed manifest / transfer file */
    SX_ERR_INTEGRITY, /* hash mismatch: corruption or tampering */
    SX_ERR_ARGS,      /* invalid arguments */
    SX_ERR_CRYPTO     /* underlying crypto operation failed */
} sx_status;

/* A human-readable, static description of a status code. */
const char *sx_status_str(sx_status status);

#endif /* SECUREXFER_STATUS_H */
