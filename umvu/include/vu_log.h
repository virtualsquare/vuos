#ifndef VU_LOG_H
#define VU_LOG_H

/* VUOS logging facility.
 *
 */
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>
#include <libgen.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/* printk log level encoding (inspired by the linux kernel */
#define KERN_SOH  "\001"    /* ASCII Start Of Header */

#define PRINTK_STANDARD_LEVEL 0

/* Prefix strings for printk encoding the message log level */
#define KERN_EMERG KERN_SOH "0"  /* system is unusable */
#define KERN_ALERT KERN_SOH "1"  /* action must be taken immediately */
#define KERN_CRIT KERN_SOH "2"  /* critical conditions */
#define KERN_ERR  KERN_SOH "3"  /* error conditions */
#define KERN_WARNING  KERN_SOH "4"  /* warning conditions */
#define KERN_NOTICE KERN_SOH "5"  /* normal but significant condition */
#define KERN_INFO KERN_SOH "6"  /* informational */
#define KERN_DEBUG KERN_SOH "7" /*debug-level messages */

#define LOG_NONE  -1  /* no output */
#define LOG_DEFAULT  4  /* default loglevel */
#define LOG_VDEBUG(i)    7+i /* debug-level messages */

#define MAX_DEBUG_LEVEL 10

#define STRERROR_BUF_SIZE 1024 // see NOTES in strerror_r(3) man page

/* helper macros */
#define warning(cond) do { \
	if (!cond) { \
		char buf[STRERROR_BUF_SIZE]; \
		printk(KERN_WARNING "warning %s:%d %s\n", basename(__FILE__), __LINE__,\
				strerror_r(errno, buf, STRERROR_BUF_SIZE)); \
	} \
} while(0)

#define fatal(cond) do { \
	if (!cond) { \
		char buf[STRERROR_BUF_SIZE]; \
		printk(KERN_WARNING "fatal %s:%d %s\n", basename(__FILE__), __LINE__,\
				strerror_r(errno, buf, STRERROR_BUF_SIZE)); \
		pthread_exit(NULL); \
	} \
} while(0)

#define warning_msg(msg) do { \
	char buf[STRERROR_BUF_SIZE]; \
	printk(KERN_WARNING "warning %s:%d %s\n", basename(__FILE__), __LINE__,\
			strerror_r(errno, buf, STRERROR_BUF_SIZE)); \
} while(0)

int vprintk(const char *fmt, va_list ap);
int printk(const char *fmt, ...);

void set_console_log_level(int level);
void set_syslog_log_level(int level);
void set_log_file(char *logfile_path);

/* tagged logging. it is possible to enable/disable each log tag
	 globally or thread by thread.
	 active logging tag set is the union of those globally and locally aptivated.
	 63 tags are supported (see DEBUG_ALLTAGS) */

/* add or delete tags (tag is a string, each char is a tag to
	 be added/deleted. */
void debug_add_tags(char *tags, int local);
void debug_del_tags(char *tags, int local);
/* get the map of active tags */
void debug_get_tags(char *tags, size_t size, int local);

/* set the color of a tag (see vudebug(1) */
void debug_set_color(char *tags, const char *s);
/* parse a color mapping string */
void debug_set_color_string(const char *s);

/* debug tags may have descriptions, get/set the description */
void _debug_set_name(int index, const char *s);
void debug_get_name(char tag, char *buf, size_t bufsize);

#define debug_set_name(tag, s) \
	_debug_set_name(DEBUG_TAG2INDEX_##tag, "" s)

/* logging must be fast... if disabled.
	 printkdebug macro calls _printkdebug if tag is active.
	 the overall cost of the choice is reading two vars + one or operation + a conditinal branch */
extern uint64_t debugmask;
extern __thread uint64_t tdebugmask;

/* printk uses preprocessor magic to pprocess the first argument:
	 printkdebug(x, "message %d", intarg);
	 will be printed if tag x is active.
	 x is converted to an integer by the macros/constants here below.
	 The mapping has complexity O(1)
 */

int _printkdebug(int index, const char *fmt, ...);
#define printkdebug(tag, fmt, ...) \
	if (__builtin_expect((debugmask | tdebugmask) & (1ULL << DEBUG_TAG2INDEX_##tag), 0)) \
		_printkdebug(DEBUG_TAG2INDEX_##tag, "%s:%d " fmt "\n", \
		basename(__FILE__), __LINE__, ##__VA_ARGS__)

#define DEBUG_ALLTAGS " ABCDEFGHIJKLMNOPQRSTUVWXYZ_01234abcdefghijklmnopqrstuvwxyz56789"
#define DEBUG_NTAGS sizeof(DEBUG_ALLTAGS)
#define DEBUG_TAG2INDEX_ERR 0
#define DEBUG_TAG2INDEX_A 1
#define DEBUG_TAG2INDEX_B 2
#define DEBUG_TAG2INDEX_C 3
#define DEBUG_TAG2INDEX_D 4
#define DEBUG_TAG2INDEX_E 5
#define DEBUG_TAG2INDEX_F 6
#define DEBUG_TAG2INDEX_G 7
#define DEBUG_TAG2INDEX_H 8
#define DEBUG_TAG2INDEX_I 9
#define DEBUG_TAG2INDEX_J 10
#define DEBUG_TAG2INDEX_K 11
#define DEBUG_TAG2INDEX_L 12
#define DEBUG_TAG2INDEX_M 13
#define DEBUG_TAG2INDEX_N 14
#define DEBUG_TAG2INDEX_O 15
#define DEBUG_TAG2INDEX_P 16
#define DEBUG_TAG2INDEX_Q 17
#define DEBUG_TAG2INDEX_R 18
#define DEBUG_TAG2INDEX_S 19
#define DEBUG_TAG2INDEX_T 20
#define DEBUG_TAG2INDEX_U 21
#define DEBUG_TAG2INDEX_V 22
#define DEBUG_TAG2INDEX_W 23
#define DEBUG_TAG2INDEX_X 24
#define DEBUG_TAG2INDEX_Y 25
#define DEBUG_TAG2INDEX_Z 26
#define DEBUG_TAG2INDEX__ 27
#define DEBUG_TAG2INDEX_0 28
#define DEBUG_TAG2INDEX_1 29
#define DEBUG_TAG2INDEX_2 30
#define DEBUG_TAG2INDEX_3 31
#define DEBUG_TAG2INDEX_4 32
#define DEBUG_TAG2INDEX_a 33
#define DEBUG_TAG2INDEX_b 34
#define DEBUG_TAG2INDEX_c 35
#define DEBUG_TAG2INDEX_d 36
#define DEBUG_TAG2INDEX_e 37
#define DEBUG_TAG2INDEX_f 38
#define DEBUG_TAG2INDEX_g 39
#define DEBUG_TAG2INDEX_h 40
#define DEBUG_TAG2INDEX_i 41
#define DEBUG_TAG2INDEX_j 42
#define DEBUG_TAG2INDEX_k 43
#define DEBUG_TAG2INDEX_l 44
#define DEBUG_TAG2INDEX_m 45
#define DEBUG_TAG2INDEX_n 46
#define DEBUG_TAG2INDEX_o 47
#define DEBUG_TAG2INDEX_p 48
#define DEBUG_TAG2INDEX_q 49
#define DEBUG_TAG2INDEX_r 50
#define DEBUG_TAG2INDEX_s 51
#define DEBUG_TAG2INDEX_t 52
#define DEBUG_TAG2INDEX_u 53
#define DEBUG_TAG2INDEX_v 54
#define DEBUG_TAG2INDEX_w 55
#define DEBUG_TAG2INDEX_x 56
#define DEBUG_TAG2INDEX_y 57
#define DEBUG_TAG2INDEX_z 58
#define DEBUG_TAG2INDEX_5 59
#define DEBUG_TAG2INDEX_6 60
#define DEBUG_TAG2INDEX_7 61
#define DEBUG_TAG2INDEX_8 62
#define DEBUG_TAG2INDEX_9 63
#endif
