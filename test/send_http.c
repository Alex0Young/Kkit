#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAX_BUF_SIZE 1024

int main() {
    // 创建套接字
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // 准备目标服务器的地址结构
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(50004); // HTTP默认端口为80，这里使用了50002
    server_addr.sin_addr.s_addr = inet_addr("123.249.89.38"); // 目标服务器IP地址

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    // 构造HTTP GET请求
    char *request = "GET / HTTP/1.1\r\n"
                    "Host: 123.249.89.38:50004\r\n"
                    "Connection: close\r\n\r\n";

    // 发送请求
    if (send(sock, request, strlen(request), 0) < 0) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    // 接收响应并打印
    // char response[MAX_BUF_SIZE];
    // int bytes_received;
    // while ((bytes_received = recv(sock, response, MAX_BUF_SIZE - 1, 0)) > 0) {
    //     response[bytes_received] = '\0';
    //     printf("%s", response);
    // }

    // if (bytes_received < 0) {
    //     perror("Receive failed");
    // }

    // 关闭套接字
    close(sock);

    return 0;
}
