#include <stdio.h>
#include <stdlib.h>

static void mark(const char *name) {
    const char *path = getenv("OLOPA_SQL_GUARD_MARKER");
    if (path == NULL) return;
    FILE *file = fopen(path, "a");
    if (file == NULL) return;
    fprintf(file, "%s\n", name);
    fclose(file);
}

void *PQexec(void *connection, const char *query) {
    (void)connection; (void)query;
    mark("PQexec");
    return (void *)1;
}

void *PQexecParams(void *connection, const char *query, int count,
                   const unsigned int *types, const char *const *values,
                   const int *lengths, const int *formats, int result_format) {
    (void)connection; (void)query; (void)count; (void)types; (void)values;
    (void)lengths; (void)formats; (void)result_format;
    mark("PQexecParams");
    return (void *)1;
}

int PQsendQuery(void *connection, const char *query) {
    (void)connection; (void)query;
    mark("PQsendQuery");
    return 1;
}

int PQsendQueryParams(void *connection, const char *query, int count,
                      const unsigned int *types, const char *const *values,
                      const int *lengths, const int *formats, int result_format) {
    (void)connection; (void)query; (void)count; (void)types; (void)values;
    (void)lengths; (void)formats; (void)result_format;
    mark("PQsendQueryParams");
    return 1;
}

void *PQprepare(void *connection, const char *name, const char *query,
                int count, const unsigned int *types) {
    (void)connection; (void)name; (void)query; (void)count; (void)types;
    return (void *)1;
}

void *PQexecPrepared(void *connection, const char *name, int count,
                     const char *const *values, const int *lengths,
                     const int *formats, int result_format) {
    (void)connection; (void)name; (void)count; (void)values; (void)lengths;
    (void)formats; (void)result_format;
    mark("PQexecPrepared");
    return (void *)1;
}

int PQsendQueryPrepared(void *connection, const char *name, int count,
                        const char *const *values, const int *lengths,
                        const int *formats, int result_format) {
    (void)connection; (void)name; (void)count; (void)values; (void)lengths;
    (void)formats; (void)result_format;
    mark("PQsendQueryPrepared");
    return 1;
}

int mysql_real_query(void *connection, const char *query, unsigned long length) {
    (void)connection; (void)query; (void)length;
    mark("mysql_real_query");
    return 0;
}

int mysql_query(void *connection, const char *query) {
    (void)connection; (void)query;
    mark("mysql_query");
    return 0;
}

int mysql_stmt_prepare(void *statement, const char *query, unsigned long length) {
    (void)statement; (void)query; (void)length;
    return 0;
}

int mysql_stmt_execute(void *statement) {
    (void)statement;
    mark("mysql_stmt_execute");
    return 0;
}
