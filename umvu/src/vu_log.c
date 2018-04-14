/*
 *   VUOS: view OS project
 *   Copyright (C) 2017  Renzo Davoli <renzo@cs.unibo.it>, Antonio Cardace <anto.cardace@gmail.com>
 *   VirtualSquare team.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <vu_log.h>
#include <r_table.h>
#include <umvu_tracer.h>

uint64_t debugmask;
__thread uint64_t tdebugmask;

#define BLACK 0
#define RED 1
#define GREEN 2
#define YELLOW 3
#define BLUE 4
#define MAGENTA 5
#define CYAN 6
#define WHITE 7

struct debugcolor {
	unsigned int valid:1;
	unsigned int bright:1;
	unsigned int dim:1;
	unsigned int underscore:1;
	unsigned int blink:1;
	unsigned int reverse:1;
	unsigned int set_foreground:1;
	unsigned int set_background:1;
	unsigned int foreground:3;
	unsigned int background:3;
};

static struct debugcolor debugcolor_table[64];
static const char *debug_tag_name[64];

static int console_current_level = LOG_DEFAULT;
static int syslog_current_level = -1;

#define MAX(X, Y) ((X) > (Y) ? (X) : (Y))

/* debugging output, (bypass pure_libc when loaded) */
int vprintk(const char *fmt, va_list ap) {
	char *s;
	int rv=0;
	int level=PRINTK_STANDARD_LEVEL;
	if (fmt[0] == *KERN_SOH) {
		/*level*/
		char tag = fmt[1];
		if (tag > '0')
			level = tag - '0';
		fmt+=2;
	}
	if (level <= console_current_level) {
		rv=vasprintf(&s, fmt, ap);
		if (rv>0)
			rv=r_write(2,s,strlen(s));
		free(s);
	}
	if (level <= syslog_current_level) {
		size_t fmtlen = strlen(fmt);
		char fmt_no_nl[fmtlen + 1];
		fmt_no_nl[0]='\0';
		strncat(fmt_no_nl, fmt, fmtlen + 1);
		if (fmt_no_nl[fmtlen - 1] == '\n')
			fmt_no_nl[fmtlen - 1] = 0;
		if (level > LOG_DEBUG)
			level = LOG_DEBUG;
		vsyslog(level, fmt_no_nl, ap);
	}
	return rv;
}

int printk(const char *fmt, ...) {
	int rv;
	va_list ap;
	va_start(ap,fmt);
	rv=vprintk(fmt,ap);
	va_end(ap);
	return rv;
}

void set_console_log_level(int level) {
	console_current_level = level;
}

void set_syslog_log_level(int level) {
	syslog_current_level = level;
}

static const char *debug_alltags = DEBUG_ALLTAGS;
/* always succeeds, may produce random results on unexpected inputs */
static int debug_tag2index(int tag) {
	char *tagp = strchr(debug_alltags, tag);
	if (tagp == NULL)
		return 0;
	else
		return tagp - debug_alltags;
}

void debug_add_tags(char *tags, int local) {
	for (; *tags; tags++) {
		int index = debug_tag2index(tags[0]);
		if (local)
			tdebugmask |= (1ULL << index);
		else
			debugmask |= (1ULL << index);
	}
}

void debug_del_tags(char *tags, int local) {
	for (; *tags; tags++) {
		int index = debug_tag2index(tags[0]);
		if (local) 
			tdebugmask &= ~(1ULL << index);
		else
			debugmask &= ~(1ULL << index);
	}
}

void debug_get_tags(char *tags, size_t size, int local) {
	size_t index;
	size_t len;
	uint64_t mask = local ? tdebugmask : debugmask;
	tags[0] = '\0';
	for (index = len = 1; index < DEBUG_NTAGS && len < size; index++) {
		if (mask & (1ULL << index)) {
			tags[len - 1] = debug_alltags[index];
			tags[len++] = '\0';
		}
	}
}

void _debug_set_name(int index, const char *s) {
	debug_tag_name[index] = s;
}

void debug_get_name(char tag, char *buf, size_t bufsize) {
	int index = debug_tag2index(tag);
	const char *name = debug_tag_name[index];
	if (name == NULL)
		name = "";
	snprintf(buf, bufsize, "%s", name);
}

static void _debug_set_tag_color(int tag, const char *s) {
	int index = debug_tag2index(tag);
	static struct debugcolor stdcolor;
	struct debugcolor color = stdcolor;
	for (; s && *s; s++) {
		switch (*s) {
			case '+': color.valid = 1; color.bright = 1; break;
			case '-': color.valid = 1; color.dim = 1; break;
			case '_': color.valid = 1; color.underscore = 1; break;
			case '*': color.valid = 1; color.blink = 1; break;
			case '#': color.valid = 1; color.reverse = 1; break;
			case 'n': color.valid = 1; color.set_foreground = 1; color.foreground = BLACK; break;
			case 'r': color.valid = 1; color.set_foreground = 1; color.foreground = RED; break;
			case 'g': color.valid = 1; color.set_foreground = 1; color.foreground = GREEN; break;
			case 'y': color.valid = 1; color.set_foreground = 1; color.foreground = YELLOW; break;
			case 'b': color.valid = 1; color.set_foreground = 1; color.foreground = BLUE; break;
			case 'm': color.valid = 1; color.set_foreground = 1; color.foreground = MAGENTA; break;
			case 'c': color.valid = 1; color.set_foreground = 1; color.foreground = CYAN; break;
			case 'w': color.valid = 1; color.set_foreground = 1; color.foreground = WHITE; break;
			case 'N': color.valid = 1; color.set_background = 1; color.background = BLACK; break;
			case 'R': color.valid = 1; color.set_background = 1; color.background = RED; break;
			case 'G': color.valid = 1; color.set_background = 1; color.background = GREEN; break;
			case 'Y': color.valid = 1; color.set_background = 1; color.background = YELLOW; break;
			case 'B': color.valid = 1; color.set_background = 1; color.background = BLUE; break;
			case 'M': color.valid = 1; color.set_background = 1; color.background = MAGENTA; break;
			case 'C': color.valid = 1; color.set_background = 1; color.background = CYAN; break;
			case 'W': color.valid = 1; color.set_background = 1; color.background = WHITE; break;
		}
	}
	debugcolor_table[index] = color;
}

void debug_set_color(char *tags, const char *s) {
	for (; *tags; tags++) 
		_debug_set_tag_color(tags[0], s);
}

void debug_set_color_string(const char *s) {
	int slen = strlen(s);
	char sc[slen];
	char *sx, *tags, *tmp;
	sc[0] = 0;
	strncat(sc, s, slen);
	for (sx = sc; (tags = strtok_r(sx, " ", &tmp)) != NULL; sx = NULL) {
		char *colstring = strchr(tags, ':');
		if (colstring) {
			*colstring++ = '\0';
			debug_set_color(tags, colstring);
		} else
			debug_set_color(tags, "");
	}
}

static int color_esc_sequence_len(struct debugcolor color) {
	int len = 3; /*ESC... m\0" */
	if (color.bright) len += 2;
	if (color.dim) len += 2;
	if (color.underscore) len += 2;
	if (color.blink) len += 2;
	if (color.reverse) len += 2;
	if (color.set_foreground) len += 3;
	if (color.set_background) len += 3;
	return len;
}

static void generate_color_esc_sequence(struct debugcolor color, char *seq) {
#if 0
	printf(" %d %d %d %d %d %d %d %d %d %d\n",
			color.valid,
			color.bright,
			color.dim,
			color.underscore,
			color.blink,
			color.reverse,
			color.set_foreground,
			color.set_background,
			color.foreground,
			color.background);
#endif

	char sep = '[';
	*seq++ = '\033';
	if (color.bright) { *seq++ = sep; *seq++ = '1'; sep = ';'; }
	if (color.dim) { *seq++ = sep; *seq++ = '2'; sep = ';'; }
	if (color.underscore) { *seq++ = sep; *seq++ = '4'; sep = ';'; }
	if (color.blink) { *seq++ = sep; *seq++ = '5'; sep = ';'; }
	if (color.reverse) { *seq++ = sep; *seq++ = '7'; sep = ';'; }
	if (color.set_foreground) {
		*seq++ = sep;
		*seq++ = '3'; 
		*seq++ = '0' + color.foreground; 
		sep = ';'; 
	}
	if (color.set_background) {
		*seq++ = sep;
		*seq++ = '4'; 
		*seq++ = '0' + color.background; 
		sep = ';'; 
	}
	*seq++ = 'm';
	*seq = 0;
}

static const char *esc_reset_color_sequence = "\033[0m";

int _printkdebug(int index, const char *fmt, ...) {
	int rv;
	struct debugcolor color = debugcolor_table[index];
	va_list ap;
	int save_errno = errno;
	va_start(ap,fmt);
	if (color.valid) {
		int fmtlen = strlen(fmt);
		int seqlen = color_esc_sequence_len(color);
		int prefixlen = strcspn(fmt, " \n");
		int postfixlen;
		const char *tag_string = debug_tag_name[index] ? debug_tag_name[index] : "";
		const char *tag_string_sep = *tag_string ? " " : "";
		int tagstringlen = strlen(tag_string) + strlen(tag_string_sep);
		int newfmtlen = fmtlen + seqlen + sizeof(esc_reset_color_sequence) + tagstringlen + 2;
		char newfmt[newfmtlen];
		char color_esc_sequence[seqlen];
		if (fmt[fmtlen-1] == '\n')
			fmtlen--;
		postfixlen = fmtlen - prefixlen;
		generate_color_esc_sequence(color, color_esc_sequence);
		snprintf(newfmt, newfmtlen, "%s%*.*s%s%s%*.*s%s\n",color_esc_sequence,
				prefixlen, prefixlen, fmt,
				tag_string_sep, tag_string,
				postfixlen, postfixlen, fmt+prefixlen, esc_reset_color_sequence);
		rv=vprintk(newfmt,ap);
	} else {
		int fmtlen = strlen(fmt);
		int prefixlen = strcspn(fmt, " \n");
		int postfixlen = fmtlen - prefixlen;
		const char *tag_string = debug_tag_name[index] ? debug_tag_name[index] : "";
		const char *tag_string_sep = *tag_string ? " " : "";
		int tagstringlen = strlen(tag_string) + strlen(tag_string_sep);
		int newfmtlen = fmtlen + tagstringlen + 2;
		char newfmt[newfmtlen];
		snprintf(newfmt, newfmtlen, "%*.*s%s%s%*.*s",
				prefixlen, prefixlen, fmt,
				tag_string_sep, tag_string,
				postfixlen, postfixlen, fmt+prefixlen);
		rv=vprintk(newfmt,ap);
	}
	va_end(ap);
	errno = save_errno;
	return rv;
}

void printkdump(void *buf, int count) {
  unsigned char *v = buf;
  int i;
  for (i=0; i<count; i++) {
    if (i%16 == 0) printk("\n");
    printk("%02x:",v[i]);
  }
  printk("\n");
}

static void *vu_log_upcall(inheritance_state_t state, void *arg) {
	void *ret_value;
  switch (state) {
    case INH_CLONE:
      ret_value = &tdebugmask;
      break;
    case INH_START:
      tdebugmask = *(uint64_t *)arg;
      break;
		default:
			break;
  }
  return ret_value;
}


__attribute__((constructor))
  static void init(void) {
    umvu_inheritance_upcall_register(vu_log_upcall);
  }

