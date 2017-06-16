/*
 * sqlparse.h
 *
 *  Created on: 2017年5月17日
 *      Author: xieshren
 */

#ifndef INCLUDE_SWPROTOCOL_SQLPARSE_H_
#define INCLUDE_SWPROTOCOL_SQLPARSE_H_

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct swSql_scanner {
	char 	*ptr, *cur, *tok, *end;
} swScanner;

struct swPlaceholder {
	char *pos;
	size_t len;
	int bindno;
	size_t qlen;		/* quoted length of value */
	char *quoted;	    /* quoted value */
	int freeq;
	struct swPlaceholder *next;
};

enum mysql_command
{
    SW_MYSQL_COM_SLEEP = 0,
    SW_MYSQL_COM_QUIT,
    SW_MYSQL_COM_INIT_DB,
    SW_MYSQL_COM_QUERY = 3,
    SW_MYSQL_COM_FIELD_LIST,
    SW_MYSQL_COM_CREATE_DB,
    SW_MYSQL_COM_DROP_DB,
    SW_MYSQL_COM_REFRESH,
    SW_MYSQL_COM_SHUTDOWN,
    SW_MYSQL_COM_STATISTICS,
    SW_MYSQL_COM_PROCESS_INFO,
    SW_MYSQL_COM_CONNECT,
    SW_MYSQL_COM_PROCESS_KILL,
    SW_MYSQL_COM_DEBUG,
    SW_MYSQL_COM_PING,
    SW_MYSQL_COM_TIME,
    SW_MYSQL_COM_DELAYED_INSERT,
    SW_MYSQL_COM_CHANGE_USER,
    SW_MYSQL_COM_BINLOG_DUMP,
    SW_MYSQL_COM_TABLE_DUMP,
    SW_MYSQL_COM_CONNECT_OUT,
    SW_MYSQL_COM_REGISTER_SLAVE,
    SW_MYSQL_COM_STMT_PREPARE,
    SW_MYSQL_COM_STMT_EXECUTE,
    SW_MYSQL_COM_STMT_SEND_LONG_DATA,
    SW_MYSQL_COM_STMT_CLOSE,
    SW_MYSQL_COM_STMT_RESET,
    SW_MYSQL_COM_SET_OPTION,
    SW_MYSQL_COM_STMT_FETCH,
    SW_MYSQL_COM_DAEMON,
    SW_MYSQL_COM_END
};

enum mysql_handshake_state
{
	SW_MYSQL_HANDSHAKE_INIT,
    SW_MYSQL_HANDSHAKE_WAIT_REQUEST,
    SW_MYSQL_HANDSHAKE_WAIT_RESULT,
    SW_MYSQL_HANDSHAKE_COMPLETED,
};

enum mysql_read_state
{
	SW_MYSQL_STATE_INIT,
    SW_MYSQL_STATE_QUERY,
    SW_MYSQL_STATE_READ_START,
    SW_MYSQL_STATE_READ_FIELD,
    SW_MYSQL_STATE_READ_ROW,
    SW_MYSQL_STATE_READ_END,
    SW_MYSQL_STATE_CLOSED,
};

enum mysql_error_code
{
    SW_MYSQL_ERR_PROTOCOL_ERROR = 1,
    SW_MYSQL_ERR_BUFFER_OVERSIZE,
    SW_MYSQL_ERR_PACKET_CORRUPT,
    SW_MYSQL_ERR_WANT_READ,
    SW_MYSQL_ERR_WANT_WRITE,
    SW_MYSQL_ERR_UNKNOWN_ERROR,
    SW_MYSQL_ERR_MYSQL_ERROR,
    SW_MYSQL_ERR_SERVER_LOST,
    SW_MYSQL_ERR_BAD_PORT,
    SW_MYSQL_ERR_RESOLV_HOST,
    SW_MYSQL_ERR_SYSTEM,
    SW_MYSQL_ERR_CANT_CONNECT,
    SW_MYSQL_ERR_BUFFER_TOO_SMALL,
    SW_MYSQL_ERR_UNEXPECT_R_STATE,
    SW_MYSQL_ERR_STRFIELD_CORRUPT,
    SW_MYSQL_ERR_BINFIELD_CORRUPT,
    SW_MYSQL_ERR_BAD_LCB,
    SW_MYSQL_ERR_LEN_OVER_BUFFER,
    SW_MYSQL_ERR_CONVLONG,
    SW_MYSQL_ERR_CONVLONGLONG,
    SW_MYSQL_ERR_CONVFLOAT,
    SW_MYSQL_ERR_CONVDOUBLE,
    SW_MYSQL_ERR_CONVTIME,
    SW_MYSQL_ERR_CONVTIMESTAMP,
    SW_MYSQL_ERR_CONVDATE
};

enum mysql_field_types
{
    SW_MYSQL_TYPE_DECIMAL,
    SW_MYSQL_TYPE_TINY,
    SW_MYSQL_TYPE_SHORT,
    SW_MYSQL_TYPE_LONG,
    SW_MYSQL_TYPE_FLOAT,
    SW_MYSQL_TYPE_DOUBLE,
    SW_MYSQL_TYPE_NULL,
    SW_MYSQL_TYPE_TIMESTAMP,
    SW_MYSQL_TYPE_LONGLONG,
    SW_MYSQL_TYPE_INT24,
    SW_MYSQL_TYPE_DATE,
    SW_MYSQL_TYPE_TIME,
    SW_MYSQL_TYPE_DATETIME,
    SW_MYSQL_TYPE_YEAR,
    SW_MYSQL_TYPE_NEWDATE,
    SW_MYSQL_TYPE_VARCHAR,
    SW_MYSQL_TYPE_BIT,
    SW_MYSQL_TYPE_NEWDECIMAL = 246,
    SW_MYSQL_TYPE_ENUM = 247,
    SW_MYSQL_TYPE_SET = 248,
    SW_MYSQL_TYPE_TINY_BLOB = 249,
    SW_MYSQL_TYPE_MEDIUM_BLOB = 250,
    SW_MYSQL_TYPE_LONG_BLOB = 251,
    SW_MYSQL_TYPE_BLOB = 252,
    SW_MYSQL_TYPE_VAR_STRING = 253,
    SW_MYSQL_TYPE_STRING = 254,
    SW_MYSQL_TYPE_GEOMETRY = 255
};

#define UTF8_MB4 "utf8mb4"
#define UTF8_MB3 "utf8"

typedef struct _mysql_charset
{
    unsigned int    nr;
    const char      *name;
    const char      *collation;
} mysql_charset;


typedef struct
{
    char *buffer;
    char *name; /* Name of column */
    char *org_name; /* Original column name, if an alias */
    char *table; /* Table of column if column was a field */
    char *org_table; /* Org table name, if table was an alias */
    char *db; /* Database for table */
    char *catalog; /* Catalog for table */
    char *def; /* Default value (set by mysql_list_fields) */
    ulong_t length; /* Width of column (create length) */
    ulong_t max_length; /* Max width for selected set */
    uint32_t name_length;
    uint32_t org_name_length;
    uint32_t table_length;
    uint32_t org_table_length;
    uint32_t db_length;
    uint32_t catalog_length;
    uint32_t def_length;
    uint32_t flags; /* Div flags */
    uint32_t decimals; /* Number of decimals in field */
    uint32_t charsetnr; /* Character set */
    enum mysql_field_types type; /* Type of field. See mysql_com.h for types */
    void *extension;
} mysql_field;

typedef union
{
    signed char stiny;
    uchar utiny;
    uchar mbool;
    short ssmall;
    unsigned short small;
    int sint;
    uint32_t uint;
    long long sbigint;
    unsigned long long ubigint;
    float mfloat;
    double mdouble;
} mysql_row;

typedef struct
{
    mysql_field *columns;
    uint16_t num_column;
    uint16_t index_column;
    uint32_t num_row;
    uint8_t wait_recv;
    uint8_t response_type;
    uint32_t packet_length :24;
    uint32_t packet_number :8;
    uint32_t error_code;
    uint32_t warnings;
    uint16_t status_code;
    char status_msg[6];
    char *server_msg;
    uint16_t l_server_msg;
    ulong_t affected_rows;
    ulong_t insert_id;
    zval *result_array;
} mysql_response_t;

typedef struct
{
    int packet_length;
    int packet_number;
    uint8_t protocol_version;
    char *server_version;
    int connection_id;
    char auth_plugin_data[21];
    uint8_t l_auth_plugin_data;
    char filler;
    int capability_flags;
    char character_set;
    int16_t status_flags;
    char reserved[10];
    char *auth_plugin_name;
    uint8_t l_auth_plugin_name;
} mysql_handshake_request;


static const mysql_charset swoole_mysql_charsets[] =
{
    { 1, "big5", "big5_chinese_ci" },
    { 3, "dec8", "dec8_swedish_ci" },
    { 4, "cp850", "cp850_general_ci" },
    { 6, "hp8", "hp8_english_ci" },
    { 7, "koi8r", "koi8r_general_ci" },
    { 8, "latin1", "latin1_swedish_ci" },
    { 5, "latin1", "latin1_german1_ci" },
    { 9, "latin2", "latin2_general_ci" },
    { 2, "latin2", "latin2_czech_cs" },
    { 10, "swe7", "swe7_swedish_ci" },
    { 11, "ascii", "ascii_general_ci" },
    { 12, "ujis", "ujis_japanese_ci" },
    { 13, "sjis", "sjis_japanese_ci" },
    { 16, "hebrew", "hebrew_general_ci" },
    { 17, "filename", "filename" },
    { 18, "tis620", "tis620_thai_ci" },
    { 19, "euckr", "euckr_korean_ci" },
    { 21, "latin2", "latin2_hungarian_ci" },
    { 27, "latin2", "latin2_croatian_ci" },
    { 22, "koi8u", "koi8u_general_ci" },
    { 24, "gb2312", "gb2312_chinese_ci" },
    { 25, "greek", "greek_general_ci" },
    { 26, "cp1250", "cp1250_general_ci" },
    { 28, "gbk", "gbk_chinese_ci" },
    { 30, "latin5", "latin5_turkish_ci" },
    { 31, "latin1", "latin1_german2_ci" },
    { 15, "latin1", "latin1_danish_ci" },
    { 32, "armscii8", "armscii8_general_ci" },
    { 33, UTF8_MB3, UTF8_MB3"_general_ci" },
    { 35, "ucs2", "ucs2_general_ci" },
    { 36, "cp866", "cp866_general_ci" },
    { 37, "keybcs2", "keybcs2_general_ci" },
    { 38, "macce", "macce_general_ci" },
    { 39, "macroman", "macroman_general_ci" },
    { 40, "cp852", "cp852_general_ci" },
    { 41, "latin7", "latin7_general_ci" },
    { 20, "latin7", "latin7_estonian_cs" },
    { 57, "cp1256", "cp1256_general_ci" },
    { 59, "cp1257", "cp1257_general_ci" },
    { 63, "binary", "binary" },
    { 97, "eucjpms", "eucjpms_japanese_ci" },
    { 29, "cp1257", "cp1257_lithuanian_ci" },
    { 31, "latin1", "latin1_german2_ci" },
    { 34, "cp1250", "cp1250_czech_cs" },
    { 42, "latin7", "latin7_general_cs" },
    { 43, "macce", "macce_bin" },
    { 44, "cp1250", "cp1250_croatian_ci" },
    { 45, UTF8_MB4, UTF8_MB4"_general_ci" },
    { 46, UTF8_MB4, UTF8_MB4"_bin" },
    { 47, "latin1", "latin1_bin" },
    { 48, "latin1", "latin1_general_ci" },
    { 49, "latin1", "latin1_general_cs" },
    { 51, "cp1251", "cp1251_general_ci" },
    { 14, "cp1251", "cp1251_bulgarian_ci" },
    { 23, "cp1251", "cp1251_ukrainian_ci" },
    { 50, "cp1251", "cp1251_bin" },
    { 52, "cp1251", "cp1251_general_cs" },
    { 53, "macroman", "macroman_bin" },
    { 54, "utf16", "utf16_general_ci" },
    { 55, "utf16", "utf16_bin" },
    { 56, "utf16le", "utf16le_general_ci" },
    { 58, "cp1257", "cp1257_bin" },
    { 60, "utf32", "utf32_general_ci" },
    { 61, "utf32", "utf32_bin" },
    { 62, "utf16le", "utf16le_bin" },
    { 64, "armscii8", "armscii8_bin" },
    { 65, "ascii", "ascii_bin" },
    { 66, "cp1250", "cp1250_bin" },
    { 67, "cp1256", "cp1256_bin" },
    { 68, "cp866", "cp866_bin" },
    { 69, "dec8", "dec8_bin" },
    { 70, "greek", "greek_bin" },
    { 71, "hebrew", "hebrew_bin" },
    { 72, "hp8", "hp8_bin" },
    { 73, "keybcs2", "keybcs2_bin" },
    { 74, "koi8r", "koi8r_bin" },
    { 75, "koi8u", "koi8u_bin" },
    { 77, "latin2", "latin2_bin" },
    { 78, "latin5", "latin5_bin" },
    { 79, "latin7", "latin7_bin" },
    { 80, "cp850", "cp850_bin" },
    { 81, "cp852", "cp852_bin" },
    { 82, "swe7", "swe7_bin" },
    { 83, UTF8_MB3, UTF8_MB3"_bin" },
    { 84, "big5", "big5_bin" },
    { 85, "euckr", "euckr_bin" },
    { 86, "gb2312", "gb2312_bin" },
    { 87, "gbk", "gbk_bin" },
    { 88, "sjis", "sjis_bin" },
    { 89, "tis620", "tis620_bin" },
    { 90, "ucs2", "ucs2_bin" },
    { 91, "ujis", "ujis_bin" },
    { 92, "geostd8", "geostd8_general_ci" },
    { 93, "geostd8", "geostd8_bin" },
    { 94, "latin1", "latin1_spanish_ci" },
    { 95, "cp932", "cp932_japanese_ci" },
    { 96, "cp932", "cp932_bin" },
    { 97, "eucjpms", "eucjpms_japanese_ci" },
    { 98, "eucjpms", "eucjpms_bin" },
    { 99, "cp1250", "cp1250_polish_ci" },
    { 128, "ucs2", "ucs2_unicode_ci" },
    { 129, "ucs2", "ucs2_icelandic_ci" },
    { 130, "ucs2", "ucs2_latvian_ci" },
    { 131, "ucs2", "ucs2_romanian_ci" },
    { 132, "ucs2", "ucs2_slovenian_ci" },
    { 133, "ucs2", "ucs2_polish_ci" },
    { 134, "ucs2", "ucs2_estonian_ci" },
    { 135, "ucs2", "ucs2_spanish_ci" },
    { 136, "ucs2", "ucs2_swedish_ci" },
    { 137, "ucs2", "ucs2_turkish_ci" },
    { 138, "ucs2", "ucs2_czech_ci" },
    { 139, "ucs2", "ucs2_danish_ci" },
    { 140, "ucs2", "ucs2_lithuanian_ci" },
    { 141, "ucs2", "ucs2_slovak_ci" },
    { 142, "ucs2", "ucs2_spanish2_ci" },
    { 143, "ucs2", "ucs2_roman_ci" },
    { 144, "ucs2", "ucs2_persian_ci" },
    { 145, "ucs2", "ucs2_esperanto_ci" },
    { 146, "ucs2", "ucs2_hungarian_ci" },
    { 147, "ucs2", "ucs2_sinhala_ci" },
    { 148, "ucs2", "ucs2_german2_ci" },
    { 149, "ucs2", "ucs2_croatian_ci" },
    { 150, "ucs2", "ucs2_unicode_520_ci" },
    { 151, "ucs2", "ucs2_vietnamese_ci" },
    { 160, "utf32", "utf32_unicode_ci" },
    { 161, "utf32", "utf32_icelandic_ci" },
    { 162, "utf32", "utf32_latvian_ci" },
    { 163, "utf32", "utf32_romanian_ci" },
    { 164, "utf32", "utf32_slovenian_ci" },
    { 165, "utf32", "utf32_polish_ci" },
    { 166, "utf32", "utf32_estonian_ci" },
    { 167, "utf32", "utf32_spanish_ci" },
    { 168, "utf32", "utf32_swedish_ci" },
    { 169, "utf32", "utf32_turkish_ci" },
    { 170, "utf32", "utf32_czech_ci" },
    { 171, "utf32", "utf32_danish_ci" },
    { 172, "utf32", "utf32_lithuanian_ci" },
    { 173, "utf32", "utf32_slovak_ci" },
    { 174, "utf32", "utf32_spanish2_ci" },
    { 175, "utf32", "utf32_roman_ci" },
    { 176, "utf32", "utf32_persian_ci" },
    { 177, "utf32", "utf32_esperanto_ci" },
    { 178, "utf32", "utf32_hungarian_ci" },
    { 179, "utf32", "utf32_sinhala_ci" },
    { 180, "utf32", "utf32_german2_ci" },
    { 181, "utf32", "utf32_croatian_ci" },
    { 182, "utf32", "utf32_unicode_520_ci" },
    { 183, "utf32", "utf32_vietnamese_ci" },
    { 192, UTF8_MB3, UTF8_MB3"_unicode_ci" },
    { 193, UTF8_MB3, UTF8_MB3"_icelandic_ci" },
    { 194, UTF8_MB3, UTF8_MB3"_latvian_ci" },
    { 195, UTF8_MB3, UTF8_MB3"_romanian_ci" },
    { 196, UTF8_MB3, UTF8_MB3"_slovenian_ci" },
    { 197, UTF8_MB3, UTF8_MB3"_polish_ci" },
    { 198, UTF8_MB3, UTF8_MB3"_estonian_ci" },
    { 199, UTF8_MB3, UTF8_MB3"_spanish_ci" },
    { 200, UTF8_MB3, UTF8_MB3"_swedish_ci" },
    { 201, UTF8_MB3, UTF8_MB3"_turkish_ci" },
    { 202, UTF8_MB3, UTF8_MB3"_czech_ci" },
    { 203, UTF8_MB3, UTF8_MB3"_danish_ci" },
    { 204, UTF8_MB3, UTF8_MB3"_lithuanian_ci" },
    { 205, UTF8_MB3, UTF8_MB3"_slovak_ci" },
    { 206, UTF8_MB3, UTF8_MB3"_spanish2_ci" },
    { 207, UTF8_MB3, UTF8_MB3"_roman_ci" },
    { 208, UTF8_MB3, UTF8_MB3"_persian_ci" },
    { 209, UTF8_MB3, UTF8_MB3"_esperanto_ci" },
    { 210, UTF8_MB3, UTF8_MB3"_hungarian_ci" },
    { 211, UTF8_MB3, UTF8_MB3"_sinhala_ci" },
    { 212, UTF8_MB3, UTF8_MB3"_german2_ci" },
    { 213, UTF8_MB3, UTF8_MB3"_croatian_ci" },
    { 214, UTF8_MB3, UTF8_MB3"_unicode_520_ci" },
    { 215, UTF8_MB3, UTF8_MB3"_vietnamese_ci" },

    { 224, UTF8_MB4, UTF8_MB4"_unicode_ci" },
    { 225, UTF8_MB4, UTF8_MB4"_icelandic_ci" },
    { 226, UTF8_MB4, UTF8_MB4"_latvian_ci" },
    { 227, UTF8_MB4, UTF8_MB4"_romanian_ci" },
    { 228, UTF8_MB4, UTF8_MB4"_slovenian_ci" },
    { 229, UTF8_MB4, UTF8_MB4"_polish_ci" },
    { 230, UTF8_MB4, UTF8_MB4"_estonian_ci" },
    { 231, UTF8_MB4, UTF8_MB4"_spanish_ci" },
    { 232, UTF8_MB4, UTF8_MB4"_swedish_ci" },
    { 233, UTF8_MB4, UTF8_MB4"_turkish_ci" },
    { 234, UTF8_MB4, UTF8_MB4"_czech_ci" },
    { 235, UTF8_MB4, UTF8_MB4"_danish_ci" },
    { 236, UTF8_MB4, UTF8_MB4"_lithuanian_ci" },
    { 237, UTF8_MB4, UTF8_MB4"_slovak_ci" },
    { 238, UTF8_MB4, UTF8_MB4"_spanish2_ci" },
    { 239, UTF8_MB4, UTF8_MB4"_roman_ci" },
    { 240, UTF8_MB4, UTF8_MB4"_persian_ci" },
    { 241, UTF8_MB4, UTF8_MB4"_esperanto_ci" },
    { 242, UTF8_MB4, UTF8_MB4"_hungarian_ci" },
    { 243, UTF8_MB4, UTF8_MB4"_sinhala_ci" },
    { 244, UTF8_MB4, UTF8_MB4"_german2_ci" },
    { 245, UTF8_MB4, UTF8_MB4"_croatian_ci" },
    { 246, UTF8_MB4, UTF8_MB4"_unicode_520_ci" },
    { 247, UTF8_MB4, UTF8_MB4"_vietnamese_ci" },
    { 248, "gb18030", "gb18030_chinese_ci" },
    { 249, "gb18030", "gb18030_bin" },
    { 254, UTF8_MB3, UTF8_MB3"_general_cs" },
    { 0, NULL, NULL},
};

static int sql_scan(swScanner *s)
{
#define MYSQL_PARSER_TEXT 1
#define MYSQL_PARSER_BIND 2
#define MYSQL_PARSER_BIND_POS 3
#define MYSQL_PARSER_EOI 4

#define RET(i) {s->cur = cursor; return i; }
#define SKIP_ONE(i) {s->cur = s->tok + 1; return i; }

#define YYCTYPE         unsigned char
#define YYCURSOR        cursor
#define YYLIMIT         s->end
#define YYMARKER        s->ptr
#define YYFILL(n)		{ RET(MYSQL_PARSER_EOI); }

	char *cursor = s->cur;
	s->tok = cursor;

	{
		YYCTYPE yych;

		if ((YYLIMIT - YYCURSOR) < 2) YYFILL(2);
		yych = *YYCURSOR;
		switch (yych) {
		case 0x00:	goto yy2;
		case '"':	goto yy3;
		case '\'':	goto yy5;
		case '(':
		case ')':
		case '*':
		case '+':
		case ',':
		case '.':	goto yy9;
		case '-':	goto yy10;
		case '/':	goto yy11;
		case ':':	goto yy6;
		case '?':	goto yy7;
		default:	goto yy12;
		}
	yy2:
		YYCURSOR = YYMARKER;
		goto yy4;
	yy3:
		yych = *(YYMARKER = ++YYCURSOR);
		if (yych >= 0x01) goto yy37;
	yy4:
		{ SKIP_ONE(MYSQL_PARSER_TEXT); }
	yy5:
		yych = *(YYMARKER = ++YYCURSOR);
		if (yych <= 0x00) goto yy4;
		goto yy32;
	yy6:
		yych = *++YYCURSOR;
		switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':	goto yy26;
		case ':':	goto yy29;
		default:	goto yy4;
		}
	yy7:
		++YYCURSOR;
		switch ((yych = *YYCURSOR)) {
		case '?':	goto yy23;
		default:	goto yy8;
		}
	yy8:
		{ RET(MYSQL_PARSER_BIND_POS); }
	yy9:
		yych = *++YYCURSOR;
		goto yy4;
	yy10:
		yych = *++YYCURSOR;
		switch (yych) {
		case '-':	goto yy21;
		default:	goto yy4;
		}
	yy11:
		yych = *(YYMARKER = ++YYCURSOR);
		switch (yych) {
		case '*':	goto yy15;
		default:	goto yy4;
		}
	yy12:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		switch (yych) {
		case 0x00:
		case '"':
		case '\'':
		case '(':
		case ')':
		case '*':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case ':':
		case '?':	goto yy14;
		default:	goto yy12;
		}
	yy14:
		{ RET(MYSQL_PARSER_TEXT); }
	yy15:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		switch (yych) {
		case '*':	goto yy17;
		default:	goto yy15;
		}
	yy17:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		switch (yych) {
		case '*':	goto yy17;
		case '/':	goto yy19;
		default:	goto yy15;
		}
	yy19:
		++YYCURSOR;
	yy20:
		{ RET(MYSQL_PARSER_TEXT); }
	yy21:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		switch (yych) {
		case '\n':
		case '\r':	goto yy20;
		default:	goto yy21;
		}
	yy23:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		switch (yych) {
		case '?':	goto yy23;
		default:	goto yy25;
		}
	yy25:
		{ RET(MYSQL_PARSER_TEXT); }
	yy26:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		switch (yych) {
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'A':
		case 'B':
		case 'C':
		case 'D':
		case 'E':
		case 'F':
		case 'G':
		case 'H':
		case 'I':
		case 'J':
		case 'K':
		case 'L':
		case 'M':
		case 'N':
		case 'O':
		case 'P':
		case 'Q':
		case 'R':
		case 'S':
		case 'T':
		case 'U':
		case 'V':
		case 'W':
		case 'X':
		case 'Y':
		case 'Z':
		case '_':
		case 'a':
		case 'b':
		case 'c':
		case 'd':
		case 'e':
		case 'f':
		case 'g':
		case 'h':
		case 'i':
		case 'j':
		case 'k':
		case 'l':
		case 'm':
		case 'n':
		case 'o':
		case 'p':
		case 'q':
		case 'r':
		case 's':
		case 't':
		case 'u':
		case 'v':
		case 'w':
		case 'x':
		case 'y':
		case 'z':	goto yy26;
		default:	goto yy28;
		}
	yy28:
		{ RET(MYSQL_PARSER_BIND); }
	yy29:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		switch (yych) {
		case ':':	goto yy29;
		default:	goto yy25;
		}
	yy31:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
	yy32:
		switch (yych) {
		case 0x00:	goto yy2;
		case '\'':	goto yy34;
		case '\\':	goto yy33;
		default:	goto yy31;
		}
	yy33:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		if (yych <= 0x00) goto yy2;
		goto yy31;
	yy34:
		++YYCURSOR;
		{ RET(MYSQL_PARSER_TEXT); }
	yy36:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
	yy37:
		switch (yych) {
		case 0x00:	goto yy2;
		case '"':	goto yy39;
		case '\\':	goto yy38;
		default:	goto yy36;
		}
	yy38:
		++YYCURSOR;
		if (YYLIMIT <= YYCURSOR) YYFILL(1);
		yych = *YYCURSOR;
		if (yych <= 0x00) goto yy2;
		goto yy36;
	yy39:
		++YYCURSOR;
		{ RET(MYSQL_PARSER_TEXT); }
	}

}

#define mysql_uint2korr(A)  (uint16_t) (((uint16_t) ((zend_uchar) (A)[0])) +\
                               ((uint16_t) ((zend_uchar) (A)[1]) << 8))
#define mysql_uint3korr(A)  (uint32_t) (((uint32_t) ((zend_uchar) (A)[0])) +\
                               (((uint32_t) ((zend_uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((zend_uchar) (A)[2])) << 16))
#define mysql_uint4korr(A)  (uint32_t) (((uint32_t) ((zend_uchar) (A)[0])) +\
                               (((uint32_t) ((zend_uchar) (A)[1])) << 8) +\
                               (((uint32_t) ((zend_uchar) (A)[2])) << 16) +\
                               (((uint32_t) ((zend_uchar) (A)[3])) << 24))

#define mysql_uint8korr(A)    ((uint64_t)(((uint32_t) ((zend_uchar) (A)[0])) +\
                                    (((uint32_t) ((zend_uchar) (A)[1])) << 8) +\
                                    (((uint32_t) ((zend_uchar) (A)[2])) << 16) +\
                                    (((uint32_t) ((zend_uchar) (A)[3])) << 24)) +\
                                    (((uint64_t) (((uint32_t) ((zend_uchar) (A)[4])) +\
                                    (((uint32_t) ((zend_uchar) (A)[5])) << 8) +\
                                    (((uint32_t) ((zend_uchar) (A)[6])) << 16) +\
                                    (((uint32_t) ((zend_uchar) (A)[7])) << 24))) << 32))

static sw_inline void mysql_pack_length(int length, char *buf)
{
    buf[2] = length >> 16;
    buf[1] = length >> 8;
    buf[0] = length;
}

static sw_inline int mysql_request(swString *sql, swString *buffer)
{
    bzero(buffer->str, 5);
    //length
    mysql_pack_length(sql->length + 1, buffer->str);
    //command
    buffer->str[4] = SW_MYSQL_COM_QUERY;
    buffer->length = 5;
    return swString_append(buffer, sql);
}

static int mysql_get_charset(char *name)
{
    const mysql_charset *c = swoole_mysql_charsets;
    while (name && c[0].nr != 0)
    {
        if (!strncasecmp(c->name, name,strlen(name)))
        {
            return c->nr;
        }
        ++c;
    }

    return SW_ERR;
}

static sw_inline int mysql_lcb_ll(char *m, ulong_t *r, char *nul, int len)
{
    if (len < 1)
    {
        return -1;
    }
    switch ((uchar) m[0])
    {

    case 251: /* fb : 1 octet */
        *r = 0;
        *nul = 1;
        return 1;

    case 252: /* fc : 2 octets */
        if (len < 3)
        {
            return -1;
        }
        *r = mysql_uint2korr(m + 1);
        *nul = 0;
        return 3;

    case 253: /* fd : 3 octets */
        if (len < 5)
        {
            return -1;
        }
        *r = mysql_uint3korr(m + 1);
        *nul = 0;
        return 4;

    case 254: /* fe */
        if (len < 9)
        {
            return -1;
        }
        *r = mysql_uint8korr(m + 1);
        *nul = 0;
        return 9;

    default:
        *r = (uchar) m[0];
        *nul = 0;
        return 1;
    }
}

static sw_inline int mysql_length_coded_binary(char *m, ulong_t *r, char *nul, int len)
{
    ulong_t val = 0;
    int retcode = mysql_lcb_ll(m, &val, nul, len);
    *r = val;
    return retcode;
}

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_SWPROTOCOL_SQLPARSE_H_ */
