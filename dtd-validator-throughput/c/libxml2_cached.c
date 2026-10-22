/* libxml2_cached: DTD-validate many DITA topics with libxml2, parsing each
 * (flattened) DTD once per thread instead of once per document.
 *
 * usage: libxml2_cached THREADS MAPFILE < file-list
 *   MAPFILE lines: PUBLIC-ID<TAB>flattened.dtd
 * Prints one "INVALID <path> <n-errors>" line per invalid file, then totals. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <libxml/parser.h>
#include <libxml/valid.h>
#include <libxml/tree.h>

#define MAXDTD 32
static char *pub[MAXDTD], *path[MAXDTD];
static int ndtd;
static char **files;
static size_t nfiles;
static atomic_size_t next_file;
static atomic_size_t total_bytes, invalid_files, total_errors;
static pthread_mutex_t out_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t loaded;
static struct timespec t_loaded;

static void count_error(void *ctx, const char *msg, ...) { (void)msg; (*(int *)ctx)++; }
static void quiet(void *ctx, const char *msg, ...) { (void)ctx; (void)msg; }

static void *worker(void *arg) {
    (void)arg;
    xmlDtdPtr dtds[MAXDTD];
    for (int i = 0; i < ndtd; i++) {
        dtds[i] = xmlParseDTD(NULL, BAD_CAST path[i]);
        if (!dtds[i]) { fprintf(stderr, "cannot parse %s\n", path[i]); exit(1); }
    }
    /* Wait until every thread has its DTDs so validation is timed alone. */
    if (pthread_barrier_wait(&loaded) == PTHREAD_BARRIER_SERIAL_THREAD)
        clock_gettime(CLOCK_MONOTONIC, &t_loaded);
    pthread_barrier_wait(&loaded);
    xmlValidCtxtPtr vctxt = xmlNewValidCtxt();
    vctxt->warning = quiet;
    for (;;) {
        size_t i = atomic_fetch_add(&next_file, 1);
        if (i >= nfiles) break;
        /* No XML_PARSE_DTDLOAD: the DOCTYPE is recorded but not fetched. */
        xmlDocPtr doc = xmlReadFile(files[i], NULL, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
        int errors = 0;
        if (!doc) {
            errors = 1;
        } else {
            FILE *f = fopen(files[i], "rb");
            if (f) { fseek(f, 0, SEEK_END); atomic_fetch_add(&total_bytes, (size_t)ftell(f)); fclose(f); }
            const xmlChar *ext = doc->intSubset ? doc->intSubset->ExternalID : NULL;
            xmlDtdPtr dtd = NULL;
            for (int d = 0; ext && d < ndtd; d++)
                if (strcmp((const char *)ext, pub[d]) == 0) dtd = dtds[d];
            if (!dtd) {
                errors = 1; /* no DOCTYPE / unknown DOCTYPE: cannot be valid */
            } else {
                vctxt->userData = &errors;
                vctxt->error = count_error;
                if (!xmlValidateDtd(vctxt, doc, dtd) && errors == 0) errors = 1;
            }
            xmlFreeDoc(doc);
        }
        if (errors) {
            atomic_fetch_add(&invalid_files, 1);
            atomic_fetch_add(&total_errors, (size_t)errors);
            pthread_mutex_lock(&out_lock);
            printf("INVALID %s %d\n", files[i], errors);
            pthread_mutex_unlock(&out_lock);
        }
    }
    xmlFreeValidCtxt(vctxt);
    for (int i = 0; i < ndtd; i++) xmlFreeDtd(dtds[i]);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s THREADS MAPFILE < files\n", argv[0]); return 2; }
    int nthreads = atoi(argv[1]);
    FILE *m = fopen(argv[2], "r");
    char line[4096];
    while (m && fgets(line, sizeof line, m) && ndtd < MAXDTD) {
        line[strcspn(line, "\n")] = 0;
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = 0;
        pub[ndtd] = strdup(line); path[ndtd] = strdup(tab + 1); ndtd++;
    }
    size_t cap = 4096;
    files = malloc(cap * sizeof *files);
    while (fgets(line, sizeof line, stdin)) {
        line[strcspn(line, "\n")] = 0;
        if (nfiles == cap) files = realloc(files, (cap *= 2) * sizeof *files);
        files[nfiles++] = strdup(line);
    }
    xmlInitParser();
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    pthread_t th[256];
    pthread_barrier_init(&loaded, NULL, nthreads);
    for (int t = 0; t < nthreads; t++) pthread_create(&th[t], NULL, worker, NULL);
    for (int t = 0; t < nthreads; t++) pthread_join(th[t], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double load = (t_loaded.tv_sec - t0.tv_sec) + (t_loaded.tv_nsec - t0.tv_nsec) / 1e9;
    double s = (t1.tv_sec - t_loaded.tv_sec) + (t1.tv_nsec - t_loaded.tv_nsec) / 1e9;
    printf("validator=libxml2-cached threads=%d files=%zu bytes=%zu invalid_files=%zu errors=%zu "
           "dtd_load_s=%.3f seconds=%.3f files_per_s=%.0f MB_per_s=%.1f\n",
           nthreads, nfiles, (size_t)total_bytes, (size_t)invalid_files, (size_t)total_errors,
           load, s, nfiles / s, total_bytes / s / 1e6);
    return 0;
}
