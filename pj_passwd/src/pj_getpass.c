#include "pj_getpass.h"
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdbool.h>

const size_t s_default_password_max = 64;
const char s_clear_line_right[] = "\33[K";

struct pj_getpass_context
{
	struct termios console_mode_org;
	struct termios console_mode;
	FILE* in;
	FILE* out;
	int fd;
};

static inline bool is_del( int c )
{
	return '\177' == c || '\10' == c;
}

static inline int pj_skip_escaped_sequence( struct pj_getpass_context* ctx )
{
	int ret = -1;
	struct termios console_mode_tmp;
	console_mode_tmp = ctx->console_mode;
	console_mode_tmp.c_cc[VTIME] = 0;
	console_mode_tmp.c_cc[VMIN] = 0;
	if( !(ret = tcsetattr( ctx->fd, TCSAFLUSH, &console_mode_tmp )) ) {
		while ( EOF != fgetc( ctx->in ) ) {}
		ret = tcsetattr( ctx->fd, TCSAFLUSH, &ctx->console_mode );
	}
	return ret;
}

static inline void cleanup_error( char** ret )
{
	free( *ret );
	*ret = 0;
}

static char* pj_getpass_masked( struct pj_getpass_context* ctx, int mask )
{
	char* ret = 0;
	size_t ret_size = 0;
	size_t cur = 0;

	if( !isprint( mask ) ) {
		mask = 0;
	}
	for(;;) {
		char c = fgetc( ctx->in );
		if( '\33' == c ) {
			if( pj_skip_escaped_sequence( ctx ) ) {
				cleanup_error( &ret );
				break;
			}
		}
		else if( is_del( c ) ) {
			if ( 0 < cur ) {
				if( mask ) {
					fputc( 0x8, ctx->out );
					fputs( s_clear_line_right, ctx->out );
				}
				ret[--cur] = 0;
			}
		}
		else {
			if( ret_size == cur) {
				size_t new_ret_size = ret_size + s_default_password_max;
				void* aux = realloc( ret, new_ret_size );
				if( !aux ) {
					cleanup_error( &ret );
					break;
				}
				ret_size = new_ret_size;
				ret = (char*)aux;
			}
			if( '\0' == c || '\n' == c || '\4' == c || EOF == c ) {
				fputc( '\n', ctx->out );
				ret[cur] = 0;
				break;
			}
			else if( isprint( c ) ) {
				if( mask ) {
					fputc( mask, ctx->out );
				}
				ret[cur++] = c;
			}
		}
	}
	return ret;
}

static void cleanup( void* arg )
{
	struct pj_getpass_context* ctx = (struct pj_getpass_context*)arg;
	if( ctx && ctx->in == ctx->out ) {
		fclose( ctx->in );
	}
}

char* pj_getpass( const char* prompt, int mask )
{
	char* ret = 0;
	struct pj_getpass_context ctx;

	if( !(ctx.in = fopen( "/dev/tty", "w+ce" )) ) {
		ctx.in = stdin;
		ctx.out = stdout;
	}
	else {
		ctx.out = ctx.in;
	}
	pthread_cleanup_push( cleanup, &ctx );
	flockfile( ctx.in );
	flockfile( ctx.out );
	ctx.fd = fileno( ctx.out );
	if( !tcgetattr( ctx.fd, &ctx.console_mode_org ) ) {
		ctx.console_mode = ctx.console_mode_org;
		ctx.console_mode.c_lflag &= ~(ECHO | ICANON);
		ctx.console_mode.c_cc[VTIME] = 0;
		ctx.console_mode.c_cc[VMIN] = 1;
		if( !tcsetattr( ctx.fd, TCSAFLUSH, &ctx.console_mode ) ) {
			if( prompt ) {
				fputs( prompt, ctx.out );
				fflush( ctx.out );
			}
			ret = pj_getpass_masked( &ctx, mask );
			if( tcsetattr( ctx.fd, TCSAFLUSH, &ctx.console_mode_org ) ) {
				free( ret );
				ret = 0;
			}
		}
	}
	funlockfile( ctx.out );
	funlockfile( ctx.in );
	pthread_cleanup_pop( 1 );
	return ret;
}
