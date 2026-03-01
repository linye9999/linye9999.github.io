#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>  // 用于errno

// 异步信号安全的输出方式（替代printf）
void safe_printf(const char *msg) {
    write(STDOUT_FILENO, msg, strlen(msg));
}

// 信号处理函数（仅调用异步安全函数）
void handler(int sig) {
    safe_printf("Arithmetic error detected (SIGFPE)\n");
    _exit(EXIT_FAILURE);  // _exit是异步安全的，替代exit
}

int main() {
    // 1. 正确注册SIGFPE信号（算术异常），用函数指针接收返回值
    void (*old_handler)(int) = signal(SIGFPE, handler);
    
    // 2. 检查信号注册是否失败
    if (old_handler == SIG_ERR) {
        perror("signal register failed");
        return EXIT_FAILURE;
    }

    // 3. 构造运行期除零（避免编译器编译期报错）
    int num = 0;
    // 先让程序运行一会儿，确认信号注册完成（可选，仅演示）
    sleep(1);
    int a = 8 / num;  // 运行期除零，触发SIGFPE

    // 以下代码永远不会执行
    printf("You will never read this sentence.\n");
    return EXIT_SUCCESS;
}
/*#include <stdio.h>
#include <signal.h>


void sig_handler(int signo) {
    if (signo == SIGINT)
        printf("Received SIGINT\n");
}

int main(void) {
    if (signal(SIGINT, sig_handler) == SIG_ERR)
        printf("\ncan't catch SIGINT\n");
    
    while(1) 
        sleep(1);
    
    return 0;
}
*/
