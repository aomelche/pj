#include <pj_utils/delete.hpp>
#include "pj_getpass.h"
#include <string>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <cstring>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <algorithm>
#include "pj_config_.h"

using namespace std;
using namespace pj;

// EXIT_SUCCESS = 0
static const int EXIT_FAILURE_ACCESSING_FILES = 1;
static const int EXIT_FAILURE_SYNTAX = 2;
static const int EXIT_FAILURE_PASSWORD = 3;
static const int EXIT_FAILURE_INTERRUPTED = 4;
static const int EXIT_FAILURE_VALUE = 5;
static const int EXIT_FAILURE_USERNAME = 6;
static const int EXIT_FAILURE_FILE_FORMAT = 7;

static const char s_version_message[] =
	"pjpasswd " PJPASSWD_VERSION_STR "\n"
	"Written by Programmer John 2016\n"
	"This is free and unencumbered software released into the public domain.\n"
	"For more information, please refer to <http://unlicense.org/>\n"
	"There is NO WARRANTY, to the extent permitted by law.\n";


static const char s_usage_message[] =
	"Usage:\n"
	"        pjpasswd [-cidDv] passwordfile username\n"
	"        pjpasswd -b[cdDv] passwordfile username password\n"
	"\n"
	"        pjpasswd -n[id] username\n"
	"        pjpasswd -nb[d] username password\n"
	"\n"
	"        pjpasswd --help\n"
	"        pjpasswd --version\n"
	" -c  Create a new file.\n"
	" -n  Don't update file; display results on stdout.\n"
	" -b  Use the password from the command line.\n"
	" -i  Read password from stdin without verification (for script usage).\n"
	" -d  Force SHA-512 encryption through crypt() system function (default).\n"
	" -D  Delete the specified user.\n"
	" -v  Verify password for the specified user.\n"
	" --help     Print this message and exit.\n"
	" --version  Print version information and exit.\n";

static const char s_options[] = "cnbidDv";
static const option s_longopts[] = {
	{ "help", no_argument, 0, 1 },
	{ "version", no_argument, 0, 2 },
	{ 0, 0, 0, 0 }
};

static const char s_salt_symbols[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";

struct base64_encode
{
	unsigned int t0 : 6;
	unsigned int t1 : 6;
	unsigned int t2 : 6;
	unsigned int t3 : 6;
};

static void random_to_salt( const char r[12], char s[16] )
{
	const char* r_end = r + 12;
	do {
		const base64_encode *enc = reinterpret_cast<const base64_encode*>(r);
		s[0] = s_salt_symbols[enc->t0];
		s[1] = s_salt_symbols[enc->t1];
		s[2] = s_salt_symbols[enc->t2];
		s[3] = s_salt_symbols[enc->t3];
		s += 4;
		r += 3;
	} while ( r != r_end );
}

struct command_line_options
{
	command_line_options()
		: is_error (), create_file (), use_file (true), cl_password ()
		, stdin_password (), sha512 (true), delete_user (), verify_user ()
		, help (), version () {}

	string error;
	string file;
	string user;
	string password;
	bool is_error;
	bool create_file;
	bool use_file;
	bool cl_password;
	bool stdin_password;
	bool sha512;
	bool delete_user;
	bool verify_user;
	bool help;
	bool version;
};

#ifdef _DEBUG
// GDB needs operator * to display smart pointers underlying objects
// the following line explicitely instantiates it
template class std::unique_ptr<command_line_options>;
#endif

static unique_ptr<command_line_options> parse_command_line(
	int argc, char* argv[] )
{
	unique_ptr<command_line_options> ret (new command_line_options());
	int c;
	while( -1 !=
		(c = getopt_long( argc, argv, s_options, s_longopts, nullptr )) )
	{
		switch( c ) {
			case 1:
				ret->help = true;
				break;
			case 2:
				ret->version = true;
				break;
			case 'c':
				ret->create_file = true;
				break;
			case 'n':
				ret->use_file = false;
				break;
			case 'b':
				ret->cl_password = true;
				break;
			case 'i':
				ret->stdin_password = true;
				break;
			case 'd':
				ret->sha512 = true;
				break;
			case 'D':
				ret->delete_user = true;
				break;
			case 'v':
				ret->verify_user = true;
				break;
			default:
				ret->error = true;
				return ret;
		}
	}
	if( ret->help || ret->version ) {
		return ret;
	}
	if( (ret->create_file || ret->delete_user || ret->verify_user)
		&& !ret->use_file )
	{
		ret->is_error = true;
		ret->error = "Incompatible options were provided.";
		return ret;
	}
	if( ret->cl_password && ret->stdin_password ) {
		ret->is_error = true;
		ret->error = "Incompatible options were provided.";
		return ret;
	}
	if( ret->delete_user && ret->verify_user ) {
		ret->is_error = true;
		ret->error = "Incompatible options were provided.";
		return ret;
	}

	if( ret->use_file && optind != argc ) {
		ret->file = argv[optind++];
	}
	if( optind != argc ) {
		ret->user = argv[optind++];
	}
	if( ret->cl_password && optind != argc ) {
		ret->password = argv[optind++];
	}
	if( optind != argc ) {
		cerr << "Warning. Ignoring extra command line arguments." << endl;
	}

	if( ret->use_file && ret->file.empty() ) {
		ret->is_error = true;
		ret->error = "Password file name is required"
			" with the options provided.";
	}
	else if( ret->user.empty() ) {
		ret->is_error = true;
		ret->error = "User name is required.";
	}
	else if( ret->cl_password && ret->password.empty() ) {
		ret->is_error = true;
		ret->error = "Password is required with the options provided.";
	}

	return ret;
}

int main(int argc, char* argv[])
{
	unique_ptr<command_line_options> opts (parse_command_line( argc, argv ));
	if( !opts ) {
		return EXIT_FAILURE_INTERRUPTED;
	}
	if( opts->is_error ) {
		cerr << opts->error << endl
			<< s_usage_message;
		return EXIT_FAILURE_SYNTAX;
	}
	if( opts->version ) {
		cout << s_version_message;
		return EXIT_SUCCESS;
	}
	if( opts->help ) {
		cout << s_usage_message;
		return EXIT_SUCCESS;
	}

	opts->user += ":";

	// File descriptor, size and maping protection mode
	int fd = -1;
	off_t file_size = 0;
	int map_mode = 0;
	if( opts->use_file ) {
		map_mode = opts->verify_user ? PROT_READ : PROT_READ | PROT_WRITE;
		int flags = opts->create_file ? O_CREAT | O_RDWR | O_TRUNC :
			opts->verify_user ? O_RDONLY: O_RDWR;
		fd = open( opts->file.c_str(), flags, 0644 );
		struct stat st;
		if( -1 != fd && !fstat(fd, &st) && S_ISREG(st.st_mode) ) {
			file_size = st.st_size;
		}
		else {
			cerr << "Cannot open the file." << endl;
			return EXIT_FAILURE_ACCESSING_FILES;
		}
	}

	if( opts->stdin_password ) {
		cin >> opts->password;
	}
	else if( !opts->cl_password ) {
		const char* prompt =
			opts->verify_user ? "Enter password: " : "New password: ";
		unique_cptr<char> pwd (pj_getpass( prompt, 0 ));
		if( !pwd ) {
			return EXIT_FAILURE_INTERRUPTED;
		}
		if( !opts->verify_user ) {
			unique_cptr<char> pwd_check (pj_getpass( "Verify: ", 0 ));
			if( !pwd_check ) {
				return EXIT_FAILURE_INTERRUPTED;
			}
			if( strcmp( pwd.get(), pwd_check.get() ) ) {
				cerr << "Entered passwords mismatch." << endl;
				return EXIT_FAILURE_PASSWORD;
			}
		}
		opts->password = pwd.get();
	}

	// File mapping data pointer
	char* data = file_size ? reinterpret_cast<char*>(mmap( nullptr,
		file_size, map_mode, MAP_SHARED, fd, 0 )) : nullptr;
	if( reinterpret_cast<char*>(-1) == data ) {
		cerr << "File operation error." << endl;
		return EXIT_FAILURE_ACCESSING_FILES;
	}
	// Begin and end pointers to the line we need to replase, size of the line
	char* b = 0;
	char* e = 0;
	size_t s = 0;
	for( b = data,
		e = find( data, data + file_size, '\n' ),
		s = static_cast<size_t>(e - b);
		data + file_size != b;
		b = e + 1,
		e = find( b, data + file_size, '\n' ),
		s = static_cast<size_t>(e - b) )
	{
		if( opts->user.size() <= s &&
			!memcmp( opts->user.c_str(), b, opts->user.size() ) )
		{
			break;
		}
	}

	// Salt string: generated randomly or read from the file for verification
	string salt_string;
	if( opts->verify_user ) {
		b += opts->user.size();
		salt_string = string( b, e );
	}
	else if( !opts->delete_user && opts->sha512 ) {
		ifstream random_stream("/dev/urandom", ios::binary);
		char rand[12];
		char salt[16];
		random_stream.read(rand, 12);
		random_to_salt(rand, salt);
		salt_string.assign( "$6$" );
		salt_string += string(salt, 16);
		salt_string += string("$", 1);
	}

	// Line holding password hash and salt, calculated from inputs
	string passwd_line;
	if( !opts->delete_user ) {
		const char* p = crypt( opts->password.c_str(), salt_string.c_str() );
		if( !p ) {
			if( EINVAL == errno ) {
				cerr << "Wrong file format." << endl;
				return EXIT_FAILURE_FILE_FORMAT;
			}
			else {
				cerr << "System error." << endl;
				return EXIT_FAILURE_INTERRUPTED;
			}
		}
		passwd_line.assign( p );
		if( opts->verify_user ) {
			if( passwd_line == salt_string ) {
				return EXIT_SUCCESS;
			}
			else {
				cerr << "Wrong login or password." << endl;
				return EXIT_FAILURE_PASSWORD;
			}
		}
		passwd_line = opts->user + passwd_line;
	}

	if( !opts->use_file ) {
		cout << passwd_line << endl;
	}
	else {
		if( s < passwd_line.size() ) {
			if( b != data && '\n' != b[-1] ) {
				passwd_line.insert( 0, 1, '\n' );
			}
			off_t new_file_size = file_size + passwd_line.size() - s;
			if(	posix_fallocate( fd, 0, new_file_size ) ) {
				cerr << "File operation error." << endl;
				return EXIT_FAILURE_ACCESSING_FILES;
			}
			if( data && munmap( data, file_size ) ) {
				cerr << "File operation error." << endl;
				return EXIT_FAILURE_ACCESSING_FILES;
			}
			char* new_data = reinterpret_cast<char*>(mmap( nullptr,
				new_file_size, map_mode, MAP_SHARED, fd, 0 ));
			if( reinterpret_cast<char*>(-1) == new_data ) {
				cerr << "File operation error." << endl;
				return EXIT_FAILURE_ACCESSING_FILES;
			}
			ssize_t shift = new_data - data;
			b += shift;
			e += shift;
			memmove( b + passwd_line.size(), e, file_size - (e - new_data) );
		}
		else if( passwd_line.size() < s ) {
			if( passwd_line.empty() ) {
				if( b != data && '\n' == b[-1] ) {
					b = b - 1;
					s = s + 1;
				}
				else if( e != data + file_size && '\n' == e[0] ) {
					e = e + 1;
					s = s + 1;
				}
			}
			memmove( b + passwd_line.size(), e, file_size - (e - data) );
			off_t new_file_size = file_size + passwd_line.size() - s;
			if(	ftruncate( fd, new_file_size ) ) {
				cerr << "Cannot modify the file." << endl;
				return EXIT_FAILURE_ACCESSING_FILES;
			}
		}
		memcpy( b, passwd_line.c_str(), passwd_line.size() );
	}

	if( -1 != fd && close( fd ) ) {
		cerr << "Cannot write to the file" << endl;
		return EXIT_FAILURE_ACCESSING_FILES;
	}

	return EXIT_SUCCESS;
}
