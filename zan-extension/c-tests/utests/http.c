

#include "swoole.h"
#include "tests.h"
#include "Http.h"

static int http_get_path(http_parser *, const char *at, size_t length);

static int http_get_path(http_parser *parser, const char *at, size_t length)
{
    printf("at=%.*s, len=%ld\n", (int) length, at, length);
    return 0;
}

bool http_get()
{
    char *dir = swoole_dirname(__FILE__);
    char file[256];
    sprintf(file, "%s/http/get.txt", dir);

    swString *content = swoole_file_get_contents(file);
    if (!content)
    {
        return -1;
    }
    
    http_parser parser;
    http_parser_settings setting;
    bzero(&setting, sizeof(setting));
    setting.on_path = http_get_path;

    http_parser_init(&parser, HTTP_REQUEST);

    size_t parse_n = http_parser_execute(&parser, &setting, content->str, content->size);

    printf("parse_n=%ld, finish=%d, content_length=%ld\n", parse_n, parser.nread, parser.content_length);

    free(dir);
    swString_free(content);
    return 0;
}

bool http_post()
{
    char *dir = swoole_dirname(__FILE__);
    char file[256];
    sprintf(file, "%s/http/post.txt", dir);

    swString *content = swoole_file_get_contents(file);
    if (!content)
    {
        return -1;
    }

    http_parser parser;
    http_parser_settings setting;
    bzero(&setting, sizeof(setting));
    setting.on_path = http_get_path;

    http_parser_init(&parser, HTTP_REQUEST);

    size_t parse_n = http_parser_execute(&parser, &setting, content->str, content->size);

    printf("parse_n=%ld, finish=%d, content_length=%ld\n", parse_n, parser.nread, parser.content_length);

    free(dir);
    swString_free(content);
    return 0;
}
