/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
 | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | zan@zanphp.io so we can mail you a copy immediately.                 |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 |         Zan Group   <zan@zanphp.io>                                  |
 +----------------------------------------------------------------------+
 */

#ifndef SWOOLE_MYSQL_H_
#define SWOOLE_MYSQL_H_

#ifdef SW_USE_MYSQLND
#include "ext/mysqlnd/mysqlnd.h"
#include "ext/mysqlnd/mysqlnd_charset.h"
#endif

#include "swProtocol/sqlparse.h"


#define SW_MYSQL_CLIENT_CONNECT_WITH_DB          8
#define SW_MYSQL_CLIENT_PROTOCOL_41              512
#define SW_MYSQL_CLIENT_PLUGIN_AUTH              (1UL << 19)
#define SW_MYSQL_CLIENT_CONNECT_ATTRS            (1UL << 20)
#define SW_MYSQL_CLIENT_SECURE_CONNECTION        32768

enum mysql_placeholder_support {
    MYSQL_PLACEHOLDER_NONE=0,
    MYSQL_PLACEHOLDER_NAMED=1,
    MYSQL_PLACEHOLDER_POSITIONAL=2
};

/* describes a bound parameter */
struct mysql_bound_param_data {

#if PHP_MAJOR_VERSION < 7
    zval *parameter;                /* the variable itself */
    long paramno; /* if -1, then it has a name, and we don't know the index *yet* */
    char *name;
    int name_len;
#else
    zval parameter;             /* the variable itself */
    zend_long paramno; /* if -1, then it has a name, and we don't know the index *yet* */
    zend_string *name;
#endif
    //HashTable *bound_params;

    //zend_long max_value_len;  /* as a hint for pre-allocation */
    //enum mysql_param_type param_type; /* desired or suggested variable type */
    //int is_param;     /* parameter or column ? */
};

//typedef struct mysql_bound_param_stmt      mysql_bound_param_stmt;
struct mysql_bound_param_stmt {
    HashTable *bound_params;
    /* if true, the statement supports placeholders and can implement
     * bindParam() for its prepared statements, if false, PDO should
     * emulate prepare and bind on its behalf */
    unsigned supports_placeholders:2;
};

typedef struct
{
    char *host;
    char *user;
    char *password;
    char *database;

    zend_size_t host_len;
    zend_size_t user_len;
    zend_size_t password_len;
    zend_size_t database_len;

    long port;
    double timeout;

    int capability_flags;
    int max_packet_size;
    char character_set;
    int packet_length;
    char buf[512];

    uint16_t error_code;
    char *error_msg;
    uint16_t error_length;
} mysql_connector;

typedef struct
{
    uint8_t released;
    /* if true, commit or rollBack is allowed to be called */
    uint8_t in_txn;
    uint8_t state;
    uint8_t handshake;
    swString *buffer;
    swClient *cli;
    zval *object;
    zval *callback;
    zval *onConnect;
    zval *onClose;
    zval *onTimeout;
    int fd;

    mysql_connector connector;
    mysql_response_t response;
#if PHP_MAJOR_VERSION >= 7
    zval _object;
    zval _onClose;
#endif
} mysql_client;

static sw_inline int mysql_read_eof(mysql_client *client, char *buffer, int n_buf)
{
    //EOF, length (3byte) + id(1byte) + 0xFE + warning(2byte) + status(2byte)
    if (n_buf < 9)
    {
        client->response.wait_recv = 1;
        return SW_ERR;
    }

    client->response.packet_length = mysql_uint3korr(buffer);
    client->response.packet_number = buffer[3];

    //not EOF packet
    uint8_t eof = buffer[4];
    if (eof != 0xfe)
    {
        return SW_ERR;
    }

    client->response.warnings = mysql_uint2korr(buffer + 5);
    client->response.status_code = mysql_uint2korr(buffer + 7);

    return SW_OK;
}

static int mysql_handshake(mysql_connector *connector, char *buf, int len)
{
    char *tmp = buf;

    /**
     * handshake request
     */
    mysql_handshake_request request;
    bzero(&request, sizeof(request));

    request.packet_length = mysql_uint3korr(tmp);
    //continue to wait for data
    if (len < request.packet_length + 4)
    {
        return 0;
    }

    request.packet_number = tmp[3];
    tmp += 4;

    request.protocol_version = *tmp;
    tmp += 1;

    //ERROR Packet
    if (request.protocol_version == 0xff)
    {
        connector->error_code = *(uint16_t *) tmp;
        connector->error_msg = tmp + 2;
        connector->error_length = request.packet_length - 3;
        return -1;
    }

    //1              [0a] protocol version
    request.server_version = tmp;
    tmp += (strlen(request.server_version) + 1);
    //4              connection id
    request.connection_id = *((int *) tmp);
    tmp += 4;
    //string[8]      auth-plugin-data-part-1
    memcpy(request.auth_plugin_data, tmp, 8);
    tmp += 8;
    //1              [00] filler
    request.filler = *tmp;
    tmp += 1;
    //2              capability flags (lower 2 bytes)
    memcpy(((char *) (&request.capability_flags)), tmp, 2);
    tmp += 2;

    if (tmp - buf < len)
    {
        //1              character set
        request.character_set = *tmp;
        tmp += 1;
        //2              status flags
        memcpy(&request.status_flags, tmp, 2);
        tmp += 2;
        //2              capability flags (upper 2 bytes)
        memcpy(((char *) (&request.capability_flags) + 2), tmp, 2);
        tmp += 2;

        request.l_auth_plugin_data = *tmp;
        tmp += 1;

        memcpy(&request.reserved, tmp, sizeof(request.reserved));
        tmp += sizeof(request.reserved);

        if (request.capability_flags & SW_MYSQL_CLIENT_SECURE_CONNECTION)
        {
            int len = MAX(13, request.l_auth_plugin_data - 8);
            memcpy(request.auth_plugin_data + 8, tmp, len);
            tmp += len;
        }

        if (request.capability_flags & SW_MYSQL_CLIENT_PLUGIN_AUTH)
        {
            request.auth_plugin_name = tmp;
            request.l_auth_plugin_name = MIN(strlen(tmp), len - (tmp - buf));
        }
    }

    int value;
    tmp = connector->buf + 4;

    //capability flags, CLIENT_PROTOCOL_41 always set
    value = SW_MYSQL_CLIENT_PROTOCOL_41 | SW_MYSQL_CLIENT_SECURE_CONNECTION | SW_MYSQL_CLIENT_CONNECT_WITH_DB | SW_MYSQL_CLIENT_PLUGIN_AUTH;
    memcpy(tmp, &value, sizeof(value));
    tmp += 4;

    //max-packet size
    value = 300;
    memcpy(tmp, &value, sizeof(value));
    tmp += 4;

    //use the server character_set when the character_set is not set.
    if (connector->character_set == 0)
    {
        connector->character_set = request.character_set;
    }

    //character set
    *tmp = connector->character_set;
    tmp += 1;

    //string[23]     reserved (all [0])
    tmp += 23;

    //string[NUL]    username
    memcpy(tmp, connector->user, connector->user_len);
    tmp[connector->user_len] = '\0';
    tmp += (connector->user_len + 1);

    //auth-response
    if (connector->password && connector->password_len > 0)
    {
        char hash_0[20];
        bzero(hash_0, sizeof(hash_0));
        php_swoole_sha1(connector->password, connector->password_len, (uchar *) hash_0);

        char hash_1[20];
        bzero(hash_1, sizeof(hash_1));
        php_swoole_sha1(hash_0, sizeof(hash_0), (uchar *) hash_1);

        char str[40];
        memcpy(str, request.auth_plugin_data, 20);
        memcpy(str + 20, hash_1, 20);

        char hash_2[20];
        php_swoole_sha1(str, sizeof(str), (uchar *) hash_2);

        char hash_3[20];

        int *a = (int *) hash_2;
        int *b = (int *) hash_0;
        int *c = (int *) hash_3;

        int i;
        for (i = 0; i < 5; i++)
        {
            c[i] = a[i] ^ b[i];
        }

        *tmp = 20;
        memcpy(tmp + 1, hash_3, 20);
        tmp += 21;
    }
    else
    {
        *tmp = 0;
        tmp += 1;
    }

    //string[NUL]    database
    memcpy(tmp, connector->database, connector->database_len);
    tmp[connector->database_len] = '\0';
    tmp += (connector->database_len + 1);

    //string[NUL]    auth plugin name
    memcpy(tmp, request.auth_plugin_name, request.l_auth_plugin_name);
    tmp[request.l_auth_plugin_name] = '\0';
    tmp += (request.l_auth_plugin_name + 1);

    connector->packet_length = tmp - connector->buf - 4;
    mysql_pack_length(connector->packet_length, connector->buf);
    connector->buf[3] = 1;
    return 1;
}

static int mysql_decode_field(char *buf, int len, mysql_field *col)
{
    int i;
    ulong_t size;
    char nul;
    char *wh;
    int tmp_len;

    /**
     * string buffer
     */
    char *_buffer = emalloc(len);
    if (!_buffer)
    {
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    col->buffer = _buffer;

    wh = buf;

    i = 0;

    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->catalog_length = size;
    col->catalog = _buffer;
    _buffer += (size + 1);
    memcpy(col->catalog, &buf[i], size);
    col->catalog[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    db */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->db_length = size;
    col->db = _buffer;
    _buffer += (size + 1);
    memcpy(col->db, &buf[i], size);
    col->db[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    table */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->table_length = size;
    col->table = _buffer;
    _buffer += (size + 1);
    memcpy(col->table, &buf[i], size);
    col->table[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    org_table */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->org_table_length = size;
    col->org_table = _buffer;
    _buffer += (size + 1);
    memcpy(col->org_table, &buf[i], size);
    col->org_table[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    name */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->name_length = size;
    col->name = _buffer;
    _buffer += (size + 1);
    memcpy(col->name, &buf[i], size);
    col->name[size] = '\0';
    wh += size + 1;
    i += size;

    /* n (Length Coded String)    org_name */
    tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
    if (tmp_len == -1)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_BAD_LCB;
    }
    i += tmp_len;
    if (i + size > len)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }
    col->org_name_length = size;
    col->org_name = _buffer;
    _buffer += (size + 1);
    memcpy(col->org_name, &buf[i], size);
    col->org_name[size] = '\0';
    wh += size + 1;
    i += size;

    /* check len */
    if (i + 13 > len)
    {
            swoole_efree(col->buffer);
        return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
    }

    /* (filler) */
    i += 1;

    /* charset */
    col->charsetnr = mysql_uint2korr(&buf[i]);
    i += 2;

    /* length */
    col->length = mysql_uint4korr(&buf[i]);
    i += 4;

    /* type */
    col->type = (uchar) buf[i];
    i += 1;

    /* flags */
    col->flags = mysql_uint3korr(&buf[i]);
    i += 2;

    /* decimals */
    col->decimals = buf[i];
    i += 1;

    /* filler */
    i += 2;

    /* default - a priori facultatif */
    if (len - i > 0)
    {
        tmp_len = mysql_length_coded_binary(&buf[i], &size, &nul, len - i);
        if (tmp_len == -1)
        {
                swoole_efree(col->buffer);
            return -SW_MYSQL_ERR_BAD_LCB;
        }
        i += tmp_len;
        if (i + size > len)
        {
                swoole_efree(col->buffer);
            return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
        }
        col->def_length = size;
        col->def = _buffer;
        //_buffer += (size + 1);
        memcpy(col->def, &buf[i], size);
        col->def[size] = '\0';
        wh += size + 1;
        i += size;
    }
    else
    {
        col->def = NULL;
        col->def_length = 0;
    }

    /* set write pointer */
    return wh - buf;
}

static int mysql_read_columns(mysql_client *client)
{
    char *buffer = client->buffer->str + client->buffer->offset;
    uint32_t n_buf = client->buffer->length - client->buffer->offset;
    int ret;

    for (; client->response.index_column < client->response.num_column; client->response.index_column++)
    {
        if (n_buf < 4)
        {
            return SW_ERR;
        }

        client->response.packet_length = mysql_uint3korr(buffer);

        //no enough data
        if (n_buf - 4 < client->response.packet_length)
        {
            return SW_ERR;
        }

        client->response.packet_number = buffer[3];
        buffer += 4;
        n_buf -= 4;

        ret = mysql_decode_field(buffer, client->response.packet_length, &client->response.columns[client->response.index_column]);
        if (ret > 0)
        {
            buffer += client->response.packet_length;
            n_buf -= client->response.packet_length;
            client->buffer->offset += (client->response.packet_length + 4);
        }
        else
        {
            //swWarn("mysql_decode_field failed, code=%d.", ret);
            break;
        }
    }

    if (mysql_read_eof(client, buffer, n_buf) < 0)
    {
        return SW_ERR;
    }

    buffer += 9;
    n_buf -= 9;

    zval *result_array = client->response.result_array;
    if (!result_array)
    {
        SW_ALLOC_INIT_ZVAL(result_array);
        array_init(result_array);
        client->response.result_array = result_array;
    }

    client->buffer->offset += buffer - (client->buffer->str + client->buffer->offset);

    return SW_OK;
}

static int mysql_decode_row(mysql_client *client, char *buf, int packet_len)
{
    int read_n = 0, i;
    int tmp_len;
    ulong_t len;
    char nul;

#ifdef SW_MYSQL_STRICT_TYPE
    mysql_row row;
    char value_buffer[32];
    bzero(&row, sizeof(row));
    char *error;
    char mem;
#endif

    zval *result_array = client->response.result_array;
    zval *row_array = NULL;
    SW_MAKE_STD_ZVAL(row_array);
    array_init(row_array);

    for (i = 0; i < client->response.num_column; i++)
    {
        tmp_len = mysql_length_coded_binary(&buf[read_n], &len, &nul, packet_len - read_n);
        if (tmp_len == -1)
        {
            return -SW_MYSQL_ERR_BAD_LCB;
        }

        read_n += tmp_len;
        if (read_n + len > packet_len)
        {
            return -SW_MYSQL_ERR_LEN_OVER_BUFFER;
        }

        //swTrace("n=%d, fname=%s, name_length=%d\n", i, client->response.columns[i].name, client->response.columns[i].name_length);

        if (nul == 1)
        {
            add_assoc_null(row_array, client->response.columns[i].name);
            continue;
        }

        int type = client->response.columns[i].type;
        switch (type)
        {
        case SW_MYSQL_TYPE_NULL:
            add_assoc_null(row_array, client->response.columns[i].name);
            break;
        /* String */
        case SW_MYSQL_TYPE_TINY_BLOB:
        case SW_MYSQL_TYPE_MEDIUM_BLOB:
        case SW_MYSQL_TYPE_LONG_BLOB:
        case SW_MYSQL_TYPE_BLOB:
        case SW_MYSQL_TYPE_DECIMAL:
        case SW_MYSQL_TYPE_NEWDECIMAL:
        case SW_MYSQL_TYPE_BIT:
        case SW_MYSQL_TYPE_STRING:
        case SW_MYSQL_TYPE_VAR_STRING:
        case SW_MYSQL_TYPE_VARCHAR:
        case SW_MYSQL_TYPE_NEWDATE:
        /* Date Time */
        case SW_MYSQL_TYPE_TIME:
        case SW_MYSQL_TYPE_YEAR:
        case SW_MYSQL_TYPE_TIMESTAMP:
        case SW_MYSQL_TYPE_DATETIME:
        case SW_MYSQL_TYPE_DATE:
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
            break;
        /* Integer */
        case SW_MYSQL_TYPE_TINY:
        case SW_MYSQL_TYPE_SHORT:
        case SW_MYSQL_TYPE_INT24:
        case SW_MYSQL_TYPE_LONG:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.sint = strtol(value_buffer, &error, 10);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVLONG;
            }
            add_assoc_long(row_array, client->response.columns[i].name, row.sint);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;
        case SW_MYSQL_TYPE_LONGLONG:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.sbigint = strtoll(value_buffer, &error, 10);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVLONG;
            }
            add_assoc_long(row_array, client->response.columns[i].name, row.sbigint);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;

        case SW_MYSQL_TYPE_FLOAT:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.mfloat = strtof(value_buffer, &error);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVFLOAT;
            }
            add_assoc_double(row_array, client->response.columns[i].name, row.mfloat);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;

        case SW_MYSQL_TYPE_DOUBLE:
#ifdef SW_MYSQL_STRICT_TYPE
            memcpy(value_buffer, buf + read_n, len);
            value_buffer[len] = 0;
            row.mdouble = strtod(value_buffer, &error);
            if (*error != '\0')
            {
                return -SW_MYSQL_ERR_CONVDOUBLE;
            }
            add_assoc_double(row_array, client->response.columns[i].name, row.mdouble);
#else
            sw_add_assoc_stringl(row_array, client->response.columns[i].name, buf + read_n, len, 1);
#endif
            break;
        }
        read_n += len;
    }

    add_next_index_zval(result_array, row_array);

//#if PHP_MAJOR_VERSION > 5
//    if (row_array)
//    {
//        swoole_efree(row_array);
//    }
//#endif

    return read_n;
}

static int mysql_read_rows(mysql_client *client)
{
    char *buffer = client->buffer->str + client->buffer->offset;
    uint32_t n_buf = client->buffer->length - client->buffer->offset;
    int ret;

    //RecordSet parse
    while (n_buf > 0)
    {
        if (n_buf < 4)
        {
            client->response.wait_recv = 1;
            return SW_ERR;
        }
        //RecordSet end
        else if (n_buf == 9 && mysql_read_eof(client, buffer, n_buf) == 0)
        {
            if (client->response.columns)
            {
                int i;
                for (i = 0; i < client->response.num_column; i++)
                {
                    if (client->response.columns[i].buffer)
                    {
                        swoole_efree(client->response.columns[i].buffer);
                        client->response.columns[i].buffer = NULL;
                    }
                }
                swoole_efree(client->response.columns);
                client->response.columns = NULL;

            }
            return SW_OK;
        }

        client->response.packet_length = mysql_uint3korr(buffer);
        client->response.packet_number = buffer[3];
        buffer += 4;
        n_buf -= 4;

        //no enough data
        if (n_buf < client->response.packet_length)
        {
            client->response.wait_recv = 1;
            return SW_ERR;
        }

        //decode
        ret = mysql_decode_row(client, buffer, client->response.packet_length);
        if (ret < 0)
        {
            break;
        }

        //next row
        client->response.num_row++;
        buffer += client->response.packet_length;
        n_buf -= client->response.packet_length;
        client->buffer->offset += client->response.packet_length + 4;
    }

    return SW_ERR;
}

static int mysql_response(mysql_client *client)
{
    swString *buffer = client->buffer;
    char *p = buffer->str + buffer->offset;
    int ret;
    char nul;
    int n_buf = buffer->length - buffer->offset;

    while (n_buf > 0)
    {
        switch (client->state)
        {
        case SW_MYSQL_STATE_READ_START:
            if (buffer->length - buffer->offset < 5)
            {
                client->response.wait_recv = 1;
                return SW_ERR;
            }
            client->response.packet_length = mysql_uint3korr(p);
            client->response.packet_number = p[3];
            p += 4;
            n_buf -= 4;

            if (n_buf < client->response.packet_length)
            {
                client->response.wait_recv = 1;
                return SW_ERR;
            }

            client->response.response_type = p[0];
            p ++;
            n_buf --;

            /* error */
            if (client->response.response_type == 0xff)
            {
                client->response.error_code = mysql_uint2korr(p);
                /* status flag 1byte (#), skip.. */
                memcpy(client->response.status_msg, p + 3, 5);
                client->response.server_msg = p + 8;
                /**
                 * int<1> header  [ff] header of the ERR packet
                 * int<2>  error_code  error-code
                 * if capabilities & CLIENT_PROTOCOL_41 {
                 *  string[1] sql_state_marker    # marker of the SQL State
                 *  string[5] sql_state   SQL State
                 * }
                 */
                client->response.l_server_msg = client->response.packet_length - 9;
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* eof */
            else if (client->response.response_type == 0xfe)
            {
                client->response.warnings = mysql_uint2korr(p);
                client->response.status_code = mysql_uint2korr(p + 2);
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* ok */
            else if (client->response.response_type == 0)
            {
                /* affected rows */
                ret = mysql_length_coded_binary(p, (ulong_t *) &client->response.affected_rows, &nul, n_buf);
                n_buf -= ret;
                p += ret;

                /* insert id */
                ret = mysql_length_coded_binary(p, (ulong_t *) &client->response.insert_id, &nul, n_buf);
                n_buf -= ret;
                p += ret;

                /* server status */
                client->response.status_code = mysql_uint2korr(p);
                n_buf -= 2;
                p += 2;

                /* server warnings */
                client->response.warnings = mysql_uint2korr(p);

                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }
            /* result set */
            else
            {
                //Protocol::LengthEncodedInteger
                ret = mysql_length_coded_binary(p - 1, (ulong_t *) &client->response.num_column, &nul, n_buf + 1);
                if (ret < 0)
                {
                    return SW_ERR;
                }
                client->buffer->offset += (4 + ret);
                client->response.columns = ecalloc(client->response.num_column, sizeof(mysql_field));
                client->state = SW_MYSQL_STATE_READ_FIELD;
                break;
            }

        case SW_MYSQL_STATE_READ_FIELD:
            if (mysql_read_columns(client) < 0)
            {
                return SW_ERR;
            }
            else
            {
                client->state = SW_MYSQL_STATE_READ_ROW;
                break;
            }

        case SW_MYSQL_STATE_READ_ROW:
            if (mysql_read_rows(client) < 0)
            {
                return SW_ERR;
            }
            else
            {
                client->state = SW_MYSQL_STATE_READ_END;
                return SW_OK;
            }

        default:
            return SW_ERR;
        }
    }

    return SW_OK;
}





static int mysql_get_result(mysql_connector *connector, char *buf, int len)
{
    char *tmp = buf;
    int packet_length = mysql_uint3korr(tmp);
    if (len < packet_length + 4)
    {
        return 0;
    }
    //int packet_number = tmp[3];
    tmp += 4;

    uint8_t opcode = *tmp;
    tmp += 1;

    //ERROR Packet
    if (opcode == 0xff)
    {
        connector->error_code = *(uint16_t *) tmp;
        connector->error_msg = tmp + 2;
        connector->error_length = packet_length - 3;
        return -1;
    }
    else
    {
        return 1;
    }
}


size_t mysql_escape_slashes(char *newstr, const char * escapestr, size_t escapestr_len)
{
    const char  *newstr_s = newstr;
    const char  *newstr_e = newstr + 2 * escapestr_len;
    const char  *end = escapestr + escapestr_len;
    int escape_overflow = 0;

    for (;escapestr < end; escapestr++) {
        char esc = '\0';

        {
            switch (*escapestr) {
                case 0:
                    esc = '0';
                    break;
                case '\n':
                    esc = 'n';
                    break;
                case '\r':
                    esc = 'r';
                    break;
                case '\\':
                case '\'':
                case '"':
                    esc = *escapestr;
                    break;
                case '\032':
                    esc = 'Z';
                    break;
            }
        }
        if (esc) {
            if (newstr + 2 > newstr_e) {
                escape_overflow = 0;
                break;
            }
            /* copy escaped character */
            *newstr++ = '\\';
            *newstr++ = esc;
        } else {
            if (newstr + 1 > newstr_e) {
                escape_overflow = 1;
                break;
            }
            /* copy non escaped character */
            *newstr++ = *escapestr;
        }
    }
    *newstr = '\0';

    if (escape_overflow)
    {
        return((ulong)~0);
    }

    return((ulong)(newstr - newstr_s));
}

int mysql_handle_quoter(const char *unquoted, size_t unquotedlen, char **quoted, size_t *quotedlen)
{
    *quoted = safe_emalloc(2, unquotedlen, 3);
    *quotedlen = mysql_escape_slashes( *quoted + 1, unquoted, unquotedlen);
    (*quoted)[0] =(*quoted)[++*quotedlen] = '\'';
    (*quoted)[++*quotedlen] = '\0';
    return 1;
}

static int mysql_parse_params(struct mysql_bound_param_stmt stmt, char *inquery, size_t inquery_len,
                                                char **outquery, size_t *outquery_len TSRMLS_DC)
{
    swScanner s;
    char *ptr = NULL, *newbuffer = NULL;
    int t;
    uint32_t bindno = 0;
    int ret = 0;
    size_t newbuffer_len = 0;
    HashTable *params = NULL;
    struct mysql_bound_param_data *param = NULL;
    int query_type = MYSQL_PLACEHOLDER_NONE;
    struct swPlaceholder *placeholders = NULL, *placetail = NULL, *plc = NULL;

    ptr = *outquery;
    s.cur = inquery;
    s.end = inquery + inquery_len + 1;

    /* phase 1: look for args */
    while((t = sql_scan(&s)) != MYSQL_PARSER_EOI) {
        if (t == MYSQL_PARSER_BIND || t == MYSQL_PARSER_BIND_POS) {
            if (t == MYSQL_PARSER_BIND) {
                int len = s.cur - s.tok;
                if ((inquery < (s.cur - len)) && isalnum(*(s.cur - len - 1))) {
                    continue;
                }
                query_type |= MYSQL_PLACEHOLDER_NAMED;
            } else {
                query_type |= MYSQL_PLACEHOLDER_POSITIONAL;
            }

            plc = emalloc(sizeof(struct swPlaceholder));
            memset(plc, 0, sizeof(struct swPlaceholder));
            plc->next = NULL;
            plc->pos = s.tok;
            plc->len = s.cur - s.tok;
            plc->bindno = bindno++;

            if (placetail) {
                placetail->next = plc;
            } else {
                placeholders = plc;
            }
            placetail = plc;
        }
    }

    if (bindno == 0) {
        /* nothing to do; good! */
        return 0;
    }

    /* did the query make sense to me? */
    if (query_type == (MYSQL_PLACEHOLDER_NAMED|MYSQL_PLACEHOLDER_POSITIONAL))
    {
        /* they mixed both types; punt */
        swoole_php_fatal_error(E_WARNING,"mixed named and positional parameters");
        ret = -1;
        goto clean_up;
    }

    params = stmt.bound_params;

    /* Do we have placeholders but no bound params */
    if (bindno && !params && stmt.supports_placeholders == MYSQL_PLACEHOLDER_NONE)
    {
        swoole_php_fatal_error(E_WARNING,"no parameters were bound");
        ret = -1;
        goto clean_up;
    }

    if (params && bindno != zend_hash_num_elements(params) && stmt.supports_placeholders == MYSQL_PLACEHOLDER_NONE)
    {
        /* extra bit of validation for instances when same params are bound more than once */
        if (query_type != MYSQL_PLACEHOLDER_POSITIONAL && bindno > zend_hash_num_elements(params))
        {
            int ok = 1;
            for (plc = placeholders; plc != NULL; plc = plc->next)
            {
#if PHP_MAJOR_VERSION < 7
                if (zend_hash_find(params, plc->pos, plc->len, (void**) &param) == FAILURE)
#else
                if ((param = zend_hash_str_find_ptr(params, plc->pos, plc->len)) == NULL)
#endif
                {
                    ok = 0;
                    break;
                }
            }

            if (ok)
            {
                goto safe;
            }
        }

        swoole_php_fatal_error(E_WARNING,"number of bound variables does not match number of tokens");
        ret = -1;
        goto clean_up;
    }
safe:
    /* what are we going to do ? */
    if (stmt.supports_placeholders == MYSQL_PLACEHOLDER_NONE) {
        /* query generation */

        newbuffer_len = inquery_len;

        /* let's quote all the values */
        for (plc = placeholders; plc != NULL; plc = plc->next) {
#if PHP_MAJOR_VERSION < 7

            if (query_type == MYSQL_PLACEHOLDER_POSITIONAL)
            {
                ret = zend_hash_index_find(params, plc->bindno, (void**) &param);
            }
            else
            {
                ret = zend_hash_find(params, plc->pos, plc->len, (void**) &param);
            }
            if (ret == FAILURE)
 #else
            param =  query_type == MYSQL_PLACEHOLDER_POSITIONAL?
                                   zend_hash_index_find_ptr(params, plc->bindno):
                                   zend_hash_str_find_ptr(params, plc->pos, plc->len);

            if (param == NULL)
#endif
            {
                /* parameter was not defined */
                ret = -1;
                swoole_php_fatal_error(E_WARNING,"parameter was not defined");
                goto clean_up;
            }
            {
#if PHP_MAJOR_VERSION < 7
                zval tmp_param = *param->parameter;
                zval_copy_ctor(&tmp_param);
#else
                zval *parameter = Z_ISREF(param->parameter)? Z_REFVAL(param->parameter):&param->parameter;
                zval tmp_param;
                ZVAL_DUP(&tmp_param, parameter);
#endif
                switch (Z_TYPE(tmp_param))
                {
                    case IS_NULL:
                        plc->quoted = "NULL";
                        plc->qlen = sizeof("NULL")-1;
                        plc->freeq = 0;
                        break;
#if PHP_MAJOR_VERSION < 7
                    case IS_BOOL:
#else
                    case IS_FALSE:
                    case IS_TRUE:
#endif
                        zan_convert_to_long(&tmp_param);
                    /* fall through */
                    case IS_LONG:
                    case IS_DOUBLE:
                        sw_convert_to_string(&tmp_param);
                        plc->qlen = Z_STRLEN(tmp_param);
                        plc->quoted = estrdup(Z_STRVAL(tmp_param));
                        plc->freeq = 1;
                        break;

                    default:
                        sw_convert_to_string(&tmp_param);
                        if (!mysql_handle_quoter(Z_STRVAL(tmp_param),
                        Z_STRLEN(tmp_param), &plc->quoted, &plc->qlen))
                        {
                            /* bork */
                            ret = -1;
                            goto clean_up;
                        }

                        plc->freeq = 1;
                }

                zval_dtor(&tmp_param);
            }

            newbuffer_len += plc->qlen;
        }

//rewrite:
        /* allocate output buffer */
        newbuffer = emalloc(newbuffer_len + 1);
        bzero(newbuffer,newbuffer_len + 1);
        *outquery = newbuffer;

        /* and build the query */
        plc = placeholders;
        ptr = inquery;

        do {
            t = plc->pos - ptr;
            if (t) {
                memcpy(newbuffer, ptr, t);
                newbuffer += t;
            }
            memcpy(newbuffer, plc->quoted, plc->qlen);
            newbuffer += plc->qlen;
            ptr = plc->pos + plc->len;

            plc = plc->next;
        } while (plc);

        t = (inquery + inquery_len) - ptr;
        if (t) {
            memcpy(newbuffer, ptr, t);
            newbuffer += t;
        }
        *newbuffer = '\0';
        *outquery_len = newbuffer - *outquery;

        ret = 1;
        goto clean_up;

    }
clean_up:

    while (placeholders) {
        plc = placeholders;
        placeholders = plc->next;

        if (plc->freeq) {
            swoole_efree(plc->quoted);
        }

        swoole_efree(plc);
    }

    return ret;
}
#endif /* SWOOLE_MYSQL_H_ */
