# 每个函数的作用
1. accept_request: 处理从套接字上监听到的一个 HTTP 请求，在这里可以很大一部分地体现服务器处理请求流程。
2. bad_request: 返回给客户端这是个错误请求，HTTP 状态吗 400 BAD REQUEST.
3. cat: 读取服务器上某个文件写到 socket 套接字。
4. cannot_execute: 主要处理发生在执行 cgi 程序时出现的错误。
5. error_die: 把错误信息写到 perror 并退出。
6. execute_cgi: 运行 cgi 程序的处理，也是个主要函数。
7. get_line: 读取套接字的一行，把回车换行等情况都统一为换行符结束。
8. headers: 把 HTTP 响应的头部写到套接字。
9. not_found: 主要处理找不到请求的文件时的情况。
10. sever_file: 调用 cat 把服务器文件返回给浏览器。
11. startup: 初始化 httpd 服务，包括建立套接字，绑定端口，进行监听等。
12. unimplemented: 返回给浏览器表明收到的 HTTP 请求所用的 method 不被支持。

# 工作流程
1. 服务器启动，在指定端口或随机选取端口绑定 httpd 服务。
2. 收到一个 HTTP 请求时（其实就是 listen 的端口 accpet 的时候），派生一个线程运行 accept_request 函数。
3. 取出 HTTP 请求中的 method (GET 或 POST) 和 url,。对于 GET 方法，如果有携带参数，则 query_string 指针指向 url 中 ？ 后面的 GET 参数。
4. 格式化 url 到 path 数组，表示浏览器请求的服务器文件路径，在 tinyhttpd 中服务器文件是在 htdocs 文件夹下。当 url 以 / 结尾，或 url 是个目录，则默认在 path 中加上 index.html，表示访问主页。
5. 如果文件路径合法，对于无参数的 GET 请求，直接输出服务器文件到浏览器，即用 HTTP 格式写到套接字上，跳到（10）。其他情况（带参数 GET，POST 方式，url 为可执行文件），则调用 excute_cgi 函数执行 cgi 脚本。
6. 读取整个 HTTP 请求并丢弃，如果是 POST 则找出 Content-Length. 把 HTTP 200 状态码写到套接字。
7. 建立两个管道，cgi_input 和 cgi_output, 并 fork 一个进程。
8. 在子进程中，把 STDOUT 重定向到 cgi_outputt 的写入端，把 STDIN 重定向到 cgi_input 的读取端，关闭 cgi_input 的写入端 和 cgi_output 的读取端，设置 request_method 的环境变量，GET 的话设置 query_string 的环境变量，POST 的话设置 content_length 的环境变量，这些环境变量都是为了给 cgi 脚本调用，接着用 execl 运行 cgi 程序。
9. 在父进程中，关闭 cgi_input 的读取端 和 cgi_output 的写入端，如果 POST 的话，把 POST 数据写入 cgi_input，已被重定向到 STDIN，读取 cgi_output 的管道输出到客户端，该管道输入是 STDOUT。接着关闭所有管道，等待子进程结束。
10. 关闭与浏览器的连接，完成了一次 HTTP 请求与回应，因为 HTTP 是无连接的。