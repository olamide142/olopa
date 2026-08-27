#include <stdio.h>
#include <string.h>

void *PQexec(void *, const char *);
void *PQexecParams(void *, const char *, int, const unsigned int *,
                   const char *const *, const int *, const int *, int);
int PQsendQuery(void *, const char *);
int PQsendQueryParams(void *, const char *, int, const unsigned int *,
                      const char *const *, const int *, const int *, int);
void *PQprepare(void *, const char *, const char *, int, const unsigned int *);
void *PQexecPrepared(void *, const char *, int, const char *const *,
                     const int *, const int *, int);
int PQsendQueryPrepared(void *, const char *, int, const char *const *,
                        const int *, const int *, int);
int mysql_real_query(void *, const char *, unsigned long);
int mysql_query(void *, const char *);
int mysql_stmt_prepare(void *, const char *, unsigned long);
int mysql_stmt_execute(void *);

static const char *query = "select * from finance.ledger";

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (strcmp(argv[1], "pqexec") == 0) {
        printf("%d\n", PQexec(NULL, query) != NULL);
    } else if (strcmp(argv[1], "pqparams") == 0) {
        printf("%d\n", PQexecParams(NULL, query, 0, NULL, NULL, NULL, NULL, 0) != NULL);
    } else if (strcmp(argv[1], "pqsend") == 0) {
        printf("%d\n", PQsendQuery(NULL, query));
    } else if (strcmp(argv[1], "pqsendparams") == 0) {
        printf("%d\n", PQsendQueryParams(NULL, query, 0, NULL, NULL, NULL, NULL, 0));
    } else if (strcmp(argv[1], "pqprepared") == 0) {
        PQprepare((void *)1, "ledger", query, 0, NULL);
        printf("%d\n", PQexecPrepared((void *)1, "ledger", 0, NULL, NULL, NULL, 0) != NULL);
    } else if (strcmp(argv[1], "pqsendprepared") == 0) {
        PQprepare((void *)1, "ledger", query, 0, NULL);
        printf("%d\n", PQsendQueryPrepared((void *)1, "ledger", 0, NULL, NULL, NULL, 0));
    } else if (strcmp(argv[1], "mysqlreal") == 0) {
        printf("%d\n", mysql_real_query(NULL, query, strlen(query)));
    } else if (strcmp(argv[1], "mysqlquery") == 0) {
        printf("%d\n", mysql_query(NULL, query));
    } else if (strcmp(argv[1], "mysqlprepared") == 0) {
        mysql_stmt_prepare((void *)1, query, strlen(query));
        printf("%d\n", mysql_stmt_execute((void *)1));
    } else {
        return 64;
    }
    return 0;
}
