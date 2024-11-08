#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <time.h>
#include <unistd.h>

/*
    * HOW TO COMPILE ME:
    * gcc data_scraper.c -o data_scraper -lsqlite3
*/

void collect_data(char * data) {
    FILE *file = fopen("/proc/stat", "r");
    if (file == NULL) {
        fprintf(stderr, "Failed to open /proc/stat");
        return;
    }

    fgets(data, 256, file);
    printf("%s\n", data);
    fclose(file);
}

void store_data(sqlite3 * db, char * data) {
    char *err_msg = 0;
    char sql[512];

    snprintf(sql, sizeof(sql), "INSERT INTO cpu_usage (timestamp, data) VALUES (%ld, '%.*s');", time(NULL), data);
    int rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
    if (rc == SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
    }
}

int main(int argc, char ** argv) {
    // Create SQLite database and tables
    sqlite3 *db;
    int rc  = sqlite3_open("task_data.db", &db);
    if (rc) {
        fprintf(stderr, "Trouble opening SQLite databse: %s\n", sqlite3_errmsg(db));
        return rc;
    }

    const char * create_sql = "CREATE TABLE IF NOT EXISTS cpu_usage (timestamp INTEGER, data TEXT)";
    sqlite3_exec(db, create_sql, 0, 0, 0);

    char cpu_data[256];
    while (1) {
        collect_data(cpu_data);
        store_data(db, cpu_data);
        usleep(2000000); // sleep for 2 seconds
    }

    return 0;
}


