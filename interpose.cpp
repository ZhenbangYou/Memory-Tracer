#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <filesystem>
#include <format>
#include <string>

class InterposerException : public std::exception {
    std::string message;

public:
    InterposerException(const std::string &message_) : message(message_) {}
    const char *what() const noexcept override { return message.c_str(); }
};

static pid_t pid = getpid();
static pid_t ppid = getppid();
static thread_local pid_t tid = gettid();

class FastLogger {
    static const size_t BUFFER_SIZE = 4096;
    char buffer[BUFFER_SIZE];
    size_t cur_len = 0;
    int fd;

public:
    FastLogger(const std::filesystem::path &filepath) {
        fd = open(filepath.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            throw InterposerException(
                std::format("`open` {} failed", filepath.c_str()));
        }
    }
    void log(const char message[], size_t message_len) {
        if (cur_len + message_len >= BUFFER_SIZE) {
            size_t first_batch_len =
                std::min(BUFFER_SIZE - cur_len, message_len);
            std::copy_n(message, first_batch_len, &buffer[cur_len]);
            cur_len = BUFFER_SIZE;
            flush();
            cur_len = message_len - first_batch_len;
            std::copy_n(&message[first_batch_len], cur_len, buffer);
        } else {
            std::copy_n(message, message_len, &buffer[cur_len]);
            cur_len += message_len;
        }
    }
    void log(const char message[]) { log(message, std::strlen(message)); }
    ~FastLogger() { flush(); }

    void append_footer() {
        if (cur_len + 128 >= BUFFER_SIZE) {
            flush();
        }

        if (tid == pid) {
            cur_len += std::snprintf(
                &buffer[cur_len], 64, "\tPID\t\t%d\n\tPPID\t%d\n", pid, ppid);
        } else {
            cur_len += std::snprintf(&buffer[cur_len],
                                     64,
                                     "\tTID\t\t%d\n\tPID\t\t%d\n\tPPID\t%d\n",
                                     tid,
                                     pid,
                                     ppid);
        }

        std::chrono::time_point now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_struct;
        localtime_r(&t, &tm_struct);
        auto microsec = std::chrono::duration_cast<std::chrono::microseconds>(
                            now.time_since_epoch()) %
                        1'000'000;
        cur_len += std::snprintf(&buffer[cur_len],
                                 32,
                                 "\t[%04d-%02d-%02d %02d:%02d:%02d.%06ld]\n",
                                 tm_struct.tm_year + 1900,
                                 tm_struct.tm_mon + 1,
                                 tm_struct.tm_mday,
                                 tm_struct.tm_hour,
                                 tm_struct.tm_min,
                                 tm_struct.tm_sec,
                                 microsec.count());
    }
    void flush() {
        ssize_t _ = write(fd, buffer, cur_len);
        cur_len = 0;
    }
};

enum SyscallCategories {
    PROCESS,  // __libc_start_main_handle, exit, fork, execve
    THREAD,   // pthread_create, pthread_exit
    ALLOC,    // malloc, calloc, realloc
    MMAP,     // mmap, munmap

    CATEGORY_COUNT,
};

static thread_local FastLogger loggers[CATEGORY_COUNT]{
    {"process.log"}, {"thread.log"}, {"alloc.log"}, {"mmap.log"}};

static int (*__libc_start_main__handle)(int (*main)(int, char **, char **),
                                        int argc,
                                        char **argv,
                                        void (*init)(void),
                                        void (*fini)(void),
                                        void (*rtld_fini)(void),
                                        void *stack_end);

static decltype(&malloc) malloc__handle;
static decltype(&free) free__handle;
static decltype(&calloc) calloc__handle;
static decltype(&realloc) realloc__handle;
static decltype(&reallocarray) reallocarray__handle;

static void initialize() {
    calloc__handle = (decltype(&calloc))dlsym(RTLD_NEXT, "calloc");
    malloc__handle = (decltype(&malloc))dlsym(RTLD_NEXT, "malloc");
    free__handle = (decltype(&free))dlsym(RTLD_NEXT, "free");
    realloc__handle = (decltype(&realloc))dlsym(RTLD_NEXT, "realloc");
    reallocarray__handle =
        (decltype(&reallocarray))dlsym(RTLD_NEXT, "reallocarray");

    __libc_start_main__handle = (decltype(__libc_start_main__handle))dlsym(
        RTLD_NEXT, "__libc_start_main");
}

extern "C" void *mmap(
    void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    void *result =
        (void *)syscall(SYS_mmap, addr, length, prot, flags, fd, offset);
    return result;
}

extern "C" int munmap(void *addr, size_t length) {
    int ret = syscall(SYS_munmap, addr, length);
    return ret;
}

static void *first_call_buffer;
static size_t first_call_buffer_size;
extern "C" void *calloc(size_t n, size_t size) {
    if (first_call_buffer == nullptr) {
        first_call_buffer_size = n * size;
        first_call_buffer = mmap(nullptr,
                                 first_call_buffer_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS,
                                 0,
                                 0);
        return first_call_buffer;
    } else {
        if (calloc__handle == nullptr) {
            initialize();
        }
        return calloc__handle(n, size);
    }
}

extern "C" void *malloc(size_t size) {
    if (malloc__handle == nullptr) {
        initialize();
    }
    return malloc__handle(size);
}

extern "C" void free(void *p) {
    if (p == first_call_buffer) {
        munmap(first_call_buffer, first_call_buffer_size);
    } else {
        free__handle(p);
    }
}

struct ExitHookArg {
    int argc;
    char **argv;
};

static void exit_hook(int status, void *arg) {
    SyscallCategories category = PROCESS;
    ExitHookArg *exit_hook_arg = reinterpret_cast<ExitHookArg *>(arg);
    char buffer[32];
    size_t len = snprintf(buffer, sizeof(buffer), "exit %d\n\t", status);
    loggers[category].log(buffer, len);
    for (int i = 0; i < exit_hook_arg->argc; i++) {
        loggers[category].log(exit_hook_arg->argv[i]);
        loggers[category].log(" ");
    }
    loggers[category].log("\n");
    loggers[category].append_footer();
    for (int i = 0; i < CATEGORY_COUNT; i++) {
        loggers[category].flush();
    }
}

extern "C" int __libc_start_main(int (*main)(int, char **, char **),
                                 int argc,
                                 char **argv,
                                 void (*init)(void),
                                 void (*fini)(void),
                                 void (*rtld_fini)(void),
                                 void *stack_end) {
    SyscallCategories category = PROCESS;
    loggers[category].log("__libc_start_main\n\t");
    for (int i = 0; i < argc; i++) {
        loggers[category].log(argv[i]);
        loggers[category].log(" ");
    }
    loggers[category].log("\n");
    loggers[category].append_footer();
    on_exit(exit_hook, new ExitHookArg{.argc = argc, .argv = argv});

    if (__libc_start_main__handle == nullptr) {
        initialize();
    }

    return __libc_start_main__handle(
        main, argc, argv, init, fini, rtld_fini, stack_end);
}