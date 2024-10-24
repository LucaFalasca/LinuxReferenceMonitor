int sha256(const char *data, long data_size, char *output);
int enable_kprobes(void);
int disable_kprobes(void);

void update_access_denied_log(unsigned long data);
int put_deferred_work(void);