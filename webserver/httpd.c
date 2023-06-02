#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "w2qg0d\r\n"
#define STDIN   0
#define STDOUT  1
#define STDERR  2

void accept_request(void *);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

void accept_request(void *arg)
{
    int client = (intptr_t)arg; // 客户端 socket
    char buf[1024]; // 数据缓冲区
    size_t numchars; // buf 存储的字节数（不包含空字符）
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
    struct stat st;
    int cgi = 0;
    char *query_string = NULL;

    // 从客户端 socket 读取请求行
    numchars = get_line(client, buf, sizeof(buf));

    // 扫描请求行，获取请求方法（GET 或 POST）
    i = 0; j = 0;
    while (!ISspace(buf[i]) && (i < sizeof(method) - 1))
    {
        method[i] = buf[i];
        i++;
    }
    method[i] = '\0';
    j = i;
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST")) // 如果不是 GET 或 POST 方法则返回
    {
        unimplemented(client);
        return;
    }
    if (strcasecmp(method, "POST") == 0) // 如果是 POST 方法，则将 CGI 标志置为 1，后续交给 CGI 程序处理
        cgi = 1;

    // 扫描请求行，获取请求目标（URL 或路径）
    i = 0;
    while (ISspace(buf[j]) && (j < numchars))
        j++;
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
    url[i] = '\0';
    if (strcasecmp(method, "GET") == 0) // 如果是 GET 方法，则从 URL 中提取出查询字符串，并使用 query_string 指向该位置
    {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        if (*query_string == '?') // 如果发现查询字符
        {
            cgi = 1; // 将 CGI 标志置为 1，后续交给 CGI 程序处理
            *query_string = '\0'; // 将 '?' 字符的位置设置为字符串结束符 '\0'。这样就将查询字符串与原始的 URL 分隔开来
            query_string++; // query_string 指针后移一位，指向查询字符串的起始位置
        }
    }

    // 处理请求的文件资源
    sprintf(path, "htdocs%s", url); // 将路径字符串构建为 htdocs 后跟 url 的内容，htdocs 是服务器上存储网页文件的根目录。通过将请求的 URL 与根目录拼接，可以确定请求的文件在服务器文件系统中的路径
    if (path[strlen(path) - 1] == '/') // 如果是以斜杠结尾，说明请求的是一个目录而不是具体的文件。在这种情况下，通过追加 /index.html 的方式，将路径指向默认的索引文件
        strcat(path, "index.html");
    if (stat(path, &st) == -1) // 如果路径指定的文件或目录不存在
    {
        while ((numchars > 0) && strcmp("\n", buf)) // 循环读取并丢弃请求头部，清空接收缓冲区中的剩余数据
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client); // 向客户端发送 404 Not Found 错误响应
    }
    else // 如果路径指定的文件或目录存在
    {
        if ((st.st_mode & S_IFMT) == S_IFDIR) // 检查文件的访问权限中的文件类型位 S_IFMT，如果是目录而不是具体的文件，在这种情况下，通过追加 /index.html 的方式，将路径指向默认的索引文件
            strcat(path, "/index.html");
        if ((st.st_mode & S_IXUSR) || (st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH)) // 检查文件的访问权限中的可执行位 S_IXUSR、S_IXGRP 和 S_IXOTH，如果文件具有任意一个用户（user）、组（group）或其他（other）的可执行权限，将 cgi 标志设置为 1，表示需要执行 CGI 程序
            cgi = 1;
        if (!cgi) // 如果 cgi 标志为 0，表示请求的是静态文件，而不是需要进行 CGI 处理的动态请求。在这种情况下，调用 serve_file 函数，将文件内容发送给客户端进行服务
            serve_file(client, path);
        else // 如果 cgi 标志为 1，表示需要执行 CGI 程序，调用 execute_cgi 函数，执行相应的 CGI 程序，并将结果发送给客户端
            execute_cgi(client, path, method, query_string);
    }

    close(client);
}

void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* 将文件发给 socket
 * 参数：socket 描述符，待发送文件的指针 */
/**********************************************************************/
void cat(int client, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

/**********************************************************************/
/* 通知客户端无法执行 CGI 程序
 * 参数：socket 描述符 */
/**********************************************************************/
void cannot_execute(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

/**********************************************************************/
/* 执行 CGI 程序
 * 参数：socket 描述符，CGI 程序的路径 */
/**********************************************************************/
void execute_cgi(int client, const char *path, const char *method, const char *query_string)
{
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status;
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;

    // 扫描请求行，获取请求头部
    buf[0] = 'A'; buf[1] = '\0';
    if (strcasecmp(method, "GET") == 0) // 如果是 GET 方法
        while ((numchars > 0) && strcmp("\n", buf)) // 循环读取并丢弃请求头部，清空接收缓冲区中的剩余数据
            numchars = get_line(client, buf, sizeof(buf));
    else if (strcasecmp(method, "POST") == 0) // 如果是 POST 方法，解析请求头部，获取内容长度，其余字段不做处理
    {
        numchars = get_line(client, buf, sizeof(buf)); // 读取一行请求头部
        while ((numchars > 0) && strcmp("\n", buf)) // 检查读取行是否非空，并且不是一个换行符
        {
            buf[15] = '\0'; // 将第 16 个字符设为 \0 截断头部，仅保留字段名，方便下面做比较
            if (strcasecmp(buf, "Content-Length:") == 0) // 如果是 Content- Length: 字段，则获取内容长度
                content_length = atoi(&(buf[16]));
            numchars = get_line(client, buf, sizeof(buf)); // 迭代读取并丢弃剩余请求头部，清空接收缓冲区中的剩余数据
        }
        if (content_length == -1) // 如果未找到 Content-Length: 字段，则请求不合法
        {
            bad_request(client);
            return;
        }
    }
    else
    {
        // 其他请求方法处理逻辑
    }

    // 创建两个管道，用于与 CGI 程序进行输入和输出的交互。
    if (pipe(cgi_output) < 0) // 用于从 CGI 程序读取输出结果
    {
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0) // 用于向 CGI 程序发送输入数据
    {
        cannot_execute(client);
        return;
    }

    // 创建一个新的子进程来执行 CGI 程序，实现与 CGI 程序的并发执行
    if ((pid = fork()) < 0)
    {
        cannot_execute(client);
        return;
    }

    // 处理 CGI 程序的执行和与客户端的通信
    sprintf(buf, "HTTP/1.0 200 OK\r\n"); // 构建一个 HTTP 响应头部
    send(client, buf, strlen(buf), 0); // ，将该响应头部发送给客户端，通知客户端连接已建立
    if (pid == 0) // 子进程逻辑
    {
        char meth_env[255];
        char query_env[255];
        char length_env[255];

        dup2(cgi_output[1], STDOUT); // 将子进程的标准输出重定向到 cgi_output 管道的写入端
        dup2(cgi_input[0], STDIN); // 将子进程的标准输入重定向到 cgi_input 管道的读取端
        close(cgi_output[0]);
        close(cgi_input[1]);
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0) // GET
        {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else // POST
        {
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
        execl(path, NULL); // 执行 CGI 程序，进入 CGI 程序的代码段
        exit(0);
    }
    if (pid > 0) // 父进程逻辑
    {
        close(cgi_output[1]);
        close(cgi_input[0]);
        if (strcasecmp(method, "POST") == 0) // POST
            for (i = 0; i < content_length; i++)
            {
                recv(client, &c, 1, 0); // 从客户端接收数据
                write(cgi_input[1], &c, 1); // 将数据写入到 cgi_input 管道中
            }
        while (read(cgi_output[0], &c, 1) > 0) // 从 cgi_output 管道中读取 CGI 程序的输出数据
            send(client, &c, 1, 0); // 发送给客户端
        // 关闭管道，等待子进程结束
        close(cgi_output[0]);
        close(cgi_input[1]);
        waitpid(pid, &status, 0);
    }
}

/**********************************************************************/
/* 从套接字中获取一行数据，不管该行以换行符、回车符还是回车换行符组合结束，使用 NULL 字符终止所读取的字符串。
 * 1. 如果在缓冲区的末尾之前没有找到换行符指示器，则字符串以 NULL 字符终止。
 * 2. 如果读取到以上三种行终止符之一，字符串的最后一个字符将是换行符，并以 NULL 字符终止。
 * 参数：socket 描述符，存储数据的缓冲区，缓冲区大小
 * 返回值: 读取的字节数（不包括空字符）*/
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);
        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(sock, &c, 1, MSG_PEEK);
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return(i);
}

/**********************************************************************/
/* 返回文件的 HTTP 头部信息 */
/* 参数：socket 描述符，文件名 */
/**********************************************************************/
void headers(int client, const char *filename)
{
    char buf[1024];
    (void)filename;

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* 发送 404 NOT FOUND 信息 */
/**********************************************************************/
void not_found(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* 将文件发送给客户端
 * 参数：socket 描述符，文件名 */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];

    buf[0] = 'A'; buf[1] = '\0';
    while ((numchars > 0) && strcmp("\n", buf))
        numchars = get_line(client, buf, sizeof(buf));

    resource = fopen(filename, "r");
    if (resource == NULL)
        not_found(client);
    else
    {
        headers(client, filename);
        cat(client, resource);
    }
    fclose(resource);
}

/**********************************************************************/
/* 通知客户端所请求的网络方法尚未实现。
 * 参数：socket 描述符 */
/**********************************************************************/
void unimplemented(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* 生成监听 socket。
 * 参数：监听 socket 的端口号的指针
 * 返回值：监听 socket 的描述符 */
/**********************************************************************/
int startup(u_short *port)
{
    int httpd = 0;
    int on = 1;

    // 设置监听的地址和端口号
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;                // IPv4 协议
    listen_addr.sin_port = htons(*port);             // 监听端口号
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 监听所有可用地址

    // 创建监听套接字
    httpd = socket(PF_INET, SOCK_STREAM, 0); // IPv4, TCP, 0
    if (httpd == -1)
        error_die("socket");

    // 设置套接字 SO_REUSEADDR 选项，以便套接字关闭后立即重新绑定到同一端口，而无需等待 TIME_WAIT 状态的释放。
    if ((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)
        error_die("setsockopt failed");

    //  将监听套接字绑定上之前设置的地址信息
    if (bind(httpd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
        error_die("bind");

    // 将监听套接字设置为监听状态
    if (listen(httpd, 5) < 0) // 监听套接字描述符, 请求队列最大长度
        error_die("listen");

    // 返回监听套接字的描述符
    return(httpd);
}

/**********************************************************************/

int main(void)
{
    // test *********
    char cwd_path[1024];
    getcwd(cwd_path, sizeof(cwd_path));
    printf("there: %s\n", cwd_path);
    // test *********

    int listen_sock = -1;           // 监听套接字描述符
    u_short port = 4000;            // 监听端口号
    int client_sock = -1;           // 通信套接字描述符
    struct sockaddr_in client_addr; // 客户端地址信息
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t newthread;            // 新线程

    // 监听套接字初始化
    listen_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while (1)
    {
        // 阻塞并等待客户端的连接请求
        client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_sock == -1)
            error_die("accept");

        // 创建新线程，用于维护这组 TCP 连接
        if (pthread_create(&newthread , NULL, (void *)accept_request, (void *)(intptr_t)client_sock) != 0)
            perror("pthread_create");
    }

    close(listen_sock);

    return(0);
}