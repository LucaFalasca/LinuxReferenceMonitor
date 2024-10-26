#define MODNAME "RM_FILE_PROTECTION"
#define MAX_FILENAME_LEN 512

int sha256(const char *data, long data_size, char *output);

void update_access_denied_log(unsigned long data);
int put_deferred_work(void);

