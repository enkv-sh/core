// Test fixture only. The parent retains the PTY master; exec passes its copy as FD3.
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ttycom.h>

int main(void) {
    char name[128] = {0}; // TIOCPTYGNAME is _IOC(IOC_OUT, 't', 83, 128).
    if (ioctl(3, TIOCPTYGNAME, name) == -1) {
        perror("terminal-name ioctl");
        return 1;
    }
    char *end = memchr(name, '\0', sizeof(name));
    if (end == NULL || end == name) return 1;
    size_t length = (size_t)(end - name);
    return fwrite(name, 1, length, stdout) == length && fflush(stdout) == 0 ? 0 : 1;
}
