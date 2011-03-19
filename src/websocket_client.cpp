
#include <ctime>
#include <string>
#include <istream>
#include <ostream>
#include <sstream>
#include <iomanip>

#include <boost/random.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>

#include "rfc_md5/global.h"
#include "rfc_md5/md5.h"

#include "websocket_client.hpp"

namespace mwebsock
{



random::random()
  :gen( static_cast<unsigned long>(time(0)) )
{
}

unsigned int random::next_int(unsigned int max)
{
  typedef boost::uniform_int< unsigned int > uniform_int_t;

  uniform_int_t dist(0, max);
  boost::variate_generator<boost::mt19937&, uniform_int_t> rand(gen, dist);

  return rand() % max;

}






websocket_key_generator::websocket_key_generator()
{

  //
  // gen key_1, key_2, key_3
  //

  int spaces_1 = rand_.next_int(12)+1;
  int spaces_2 = rand_.next_int(12)+1;

  unsigned int max_1 = (rand_.next_int(0xffffffff)+1) / spaces_1;
  unsigned int max_2 = (rand_.next_int(0xffffffff)+1) / spaces_2;
	
	
  unsigned int number_1 = rand_.next_int(max_1+1);
  unsigned int number_2 = rand_.next_int(max_2+1);

  key_1_ = gen_key(spaces_1, number_1);
  key_2_ = gen_key(spaces_2, number_2);
  key_3_ = gen_bytes();
	

  //
  // gen exprected
  //

  std::ostringstream challenge;
  unsigned char* p_num1 = reinterpret_cast<unsigned char*>(&number_1);
  unsigned char* p_num2 = reinterpret_cast<unsigned char*>(&number_2);

  // create big endian with little endian cpu
  for(int i=3; i>=0; --i )
    challenge.put(p_num1[i]);

  // create big endian with little endian cpu
  for(int i=3; i>=0; --i )
    challenge.put(p_num2[i]);

  // just string
  challenge << key_3_;
  challenge << std::flush;

  expected_ = md5( challenge.str() );

}

const std::string& websocket_key_generator::key_1() const { return key_1_; }
const std::string& websocket_key_generator::key_2() const { return key_2_; }
const std::string& websocket_key_generator::key_3() const { return key_3_; }
const std::string& websocket_key_generator::expected() const { return expected_; }



std::string websocket_key_generator::gen_key(int spaces, int number)
{

  unsigned int product = spaces * number;
  std::ostringstream os;
  os << std::dec << product;
  std::string key = os.str();

  insert_chars(key);
  insert_spaces(spaces, key);

  return key;
	
}

std::string websocket_key_generator::gen_bytes()
{
  unsigned int k1 = rand_.next_int(0xffffffff);
  unsigned int k2 = rand_.next_int(0xffffffff);

  unsigned char* p_k1 = reinterpret_cast<unsigned char*>(&k1);
  unsigned char* p_k2 = reinterpret_cast<unsigned char*>(&k2);

  std::ostringstream os;

  for(int i=0; i<4; ++i )
    os.put(p_k1[i]);

  for(int i=0; i<4; ++i )
    os.put(p_k2[i]);

  os << std::flush;

  return os.str();

}

std::string websocket_key_generator::md5(const std::string& in )
{
  char* mtabl_str = const_cast<char*>(in.c_str());
  unsigned char* u_mtabl_str = reinterpret_cast<unsigned char*>(mtabl_str);
  unsigned char digest[16];

  MD5_CTX context;
  MD5Init (&context);
  MD5Update (&context, u_mtabl_str, in.length());
  MD5Final (digest, &context);

  std::ostringstream os;

  for( int i=0; i<16; ++i)
    {
      os << std::hex;
      os << std::setw(2);
      os << std::setfill('0');
      os << static_cast<int>(digest[i]);
    }

  return os.str();
}


void websocket_key_generator::insert_chars( std::string& str )
{
  int chars = rand_.next_int(12)+1;
  for( int i=0; i<chars; ++i)
    {
      int pos = rand_.next_int(str.length()-1);
      str.insert(pos, 1, get_char());
    }

}

void websocket_key_generator::insert_spaces(int spaces, std::string& str)
{
  for( int i=0; i<spaces; ++i)
    {
      int pos = rand_.next_int(str.length()-3);
      str.insert(pos+1, 1, ' ');
    }
}

char websocket_key_generator::get_char()
{
  const int fs = 0x21;
  const int fe = 0x2f; 
  const int ss = 0x3a;
  const int se = 0x7e; 
		
  int fcount = (fe+1)-fs; // count of 1st range chars
  int scount = (se+1)-ss; // count of 2nd range chars
  int ncount = ss-(fe+1); // count of numeric chars
  int ccount = fcount + scount; /* 84 */
		
  int offset = rand_.next_int(ccount); /* 0-83 */
		
  int c = offset + fs; /* skip operation chars */
  if( c <= fe )
    return c;
  else
    return c + ncount; /* skip numeric chars */
}






bool url::parse( const std::string& raw )
{
	const std::string s1 = "://";
	const std::string s2 = "/";
	const std::string s3 = ":";

	raw_ = raw;

	protocol_ = "";
	endpoint_ = "";
	path_     = "";
	host_     = "";
	port_     = "";

	size_t a = raw_.find(s1);
	if( a == std::string::npos )
	{
		return false;
    }

	protocol_ = raw_.substr(0, a);
	if( !(protocol_ == "ws" || protocol_ == "wss") )
	{
		return false;
	}

	size_t b = raw_.find(s2, a +s1.length());
	if( b != std::string::npos )
	{
		endpoint_ = raw_.substr(a +s1.length(), b-(a+s1.length()));
		path_ = raw_.substr(b);
	}
	else
	{
		endpoint_ = raw_.substr(a +s1.length());
		path_ = "/";
	}

	size_t c = endpoint_.find(s3);
	if( c != std::string::npos )
	{
		host_ = endpoint_.substr(0, c);
		port_ = endpoint_.substr(c +s3.length());
	}
	else
	{
		host_ = endpoint_;
		if( protocol_ == "ws" )
			port_ = "80";
		else if( protocol_ == "wss" )
			port_ = "443";
	}

	return true;
}







}


