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


url::url(const std::string& raw)
  :raw_(raw)
{
}

void url::parse()
{
  const std::string s1 = "://";
  const std::string s2 = "/";
  const std::string s3 = ":";

  size_t a = raw_.find(s1);
  if( a == std::string::npos )
    {
      throw url_exception("\"" + s1 + "\" not found");
    }

  protocol_ = raw_.substr(0, a);
  if( !(protocol_ == "ws" || protocol_ == "wss") )
    {
      throw url_exception("protocol \"" + protocol_ + "\" is not supported");
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

}


const std::string& url::raw() const { return raw_; }

const std::string& url::protocol() const { return protocol_; }
const std::string& url::endpoint() const { return endpoint_; }
const std::string& url::path() const { return path_; }
const std::string& url::host() const { return host_; }
const std::string& url::port() const { return port_; }





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
	






client::client(const std::string& url, const std::string& protocol)
  : ready_state_(CLOSED),
    url_(url),
    resolver_(io_service_),
    socket_(io_service_)
{}

void client::connect()
{
  ready_state_ = CONNECTING;

  try
    {
      url_.parse();
    }
  catch(const url_exception& e)
    {
      ready_state_ = CLOSED;
      throw std::domain_error("url is not correct");
    }


  boost::asio::ip::tcp::resolver::query query(url_.host(), url_.port());
  resolver_.async_resolve(query,
			  boost::bind(&client::handle_resolve, this,
				      boost::asio::placeholders::error,
				      boost::asio::placeholders::iterator));

  boost::shared_ptr<boost::thread> thread
    (new boost::thread(
  		       boost::bind(&boost::asio::io_service::run, &io_service_)));
  thread->detach();
  
}


void client::close()
{
  ready_state_ = CLOSING;

  std::ostream os(&request_);
  os.put(0x00);
  os.put(0xff);
  os.flush();

  // synchronized operation
  boost::asio::write(socket_, request_);
  io_service_.stop();
  
  ready_state_ = CLOSED;
}


void client::send(const std::string& msg)
{
  std::ostream os(&request_);
  os.put(0x00);
  os << msg;
  os.put(0xff);
  os.flush();

  boost::asio::async_write(socket_, request_,
			   boost::bind(&client::handle_write_text_frame, this,
				       boost::asio::placeholders::error));
}


int client::ready_state() const { return ready_state_; }


void client::handle_resolve(const boost::system::error_code& err,
    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
{
  if (!err)
    {
      boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
      socket_.async_connect(endpoint,
			    boost::bind(&client::handle_connect, this,
					boost::asio::placeholders::error, ++endpoint_iterator));
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}

void client::handle_connect(const boost::system::error_code& err,
    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
{
  if (!err)
    {
      std::ostream os(&request_);
      os << "GET " << url_.path() << " HTTP/1.1\r\n";
      os << "Upgrade: WebSocket" << "\r\n";
      os << "Connection: Upgrade" << "\r\n";
      os << "Host: " << url_.endpoint() << "\r\n";
      os << "Origin: " << url_.raw() << "\r\n";
      os << "Sec-WebSocket-Key1: " << key_gen_.key_1() << "\r\n";
      os << "Sec-WebSocket-Key2: " << key_gen_.key_2() << "\r\n";
      os << "\r\n";
      os << key_gen_.key_3();
      os << std::flush;

      boost::asio::async_write(socket_, request_,
			       boost::bind(&client::handle_write_request, this,
					   boost::asio::placeholders::error));
    }
  else if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator())
    {

      socket_.close();
      boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
      socket_.async_connect(endpoint,
			    boost::bind(&client::handle_connect, this,
			    boost::asio::placeholders::error, ++endpoint_iterator));
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}

void client::handle_write_request(const boost::system::error_code& err)
{
  if (!err)
    {
      boost::asio::async_read_until(socket_, response_, "\r\n",
				    boost::bind(&client::handle_read_status_line, this,
						boost::asio::placeholders::error));
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}

void client::handle_read_status_line(const boost::system::error_code& err)
{
  if (!err)
    {
      std::istream is(&response_);
      std::string http_version;
      is >> http_version;
      unsigned int status_code;
      is >> status_code;
      std::string status_message;
      std::getline(is, status_message);
      if (!is || http_version.substr(0, 5) != "HTTP/")
	{
	  ready_state_ = CLOSED;
	  on_error( INVALID_RESPONSE, "invailed response" );
	  return;
	}
      if (status_code != 101)
	{
	  ready_state_ = CLOSED;
	  on_error( BAD_STATUS, "bad status" );
	  return;
	}

      boost::asio::async_read_until(socket_, response_, "\r\n\r\n",
				    boost::bind(&client::handle_read_headers, this,
						boost::asio::placeholders::error));
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}

void client::handle_read_headers(const boost::system::error_code& err)
{
  if (!err)
    {
      std::istream is(&response_);

      // get header valiables later!
      std::string header;
      while (std::getline(is, header) && header != "\r")
	;

      if( response_.size() > 0 )
	{
	  check_handshake();
	}
	else
	{
	  boost::asio::async_read(socket_, response_,
				  boost::asio::transfer_at_least(16),
				  boost::bind(&client::handle_read_key, this,
					      boost::asio::placeholders::error));
	}
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}

void client::handle_read_key(const boost::system::error_code& err)
{
  if (!err)
    {
      check_handshake();
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}

void client::check_handshake()
{
  std::istream is(&response_);
  std::ostringstream os;
  for(int i=0; i<16; ++i)
    {
      os << std::hex
	 << std::setw(2) << std::setfill('0')
	 << is.get();
    }
  os << std::flush;

  if( key_gen_.expected() == os.str() )
    {
      ready_state_ = OPEN;
      on_open();
      if( response_.size() > 0 )
	{
	  check_frame_type();
	}
      else
	{
	  boost::asio::async_read(socket_, response_,
				  boost::asio::transfer_at_least(1),
				  boost::bind(&client::handle_read_frame_type, this,
					      boost::asio::placeholders::error));
	}
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( HANDSHAKE_FAILED, "handshake failed" );
    }

}
	
void client::handle_read_frame_type(const boost::system::error_code& err)
{
  if (!err)
    {
      check_frame_type();
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}

void client::check_frame_type()
{
  std::istream is(&response_);

  switch( is.get() )
    {
    case 0x00:
      {
	boost::asio::async_read_until(socket_, response_, 0xff,
				      boost::bind(&client::handle_read_text_frame, this,
						  boost::asio::placeholders::error));
      }
      break;
    case 0x80:
      {
	/* binary frame */
	ready_state_ = CLOSED;
	on_error( BAD_FRAME, "bad frame" );
      }
      break;
    default:
      {
	ready_state_ = CLOSED;
	on_error( BAD_FRAME, "bad frame" );
      }
      break;
    }

}

void client::handle_read_text_frame(const boost::system::error_code& err)
{
  if (!err)
    {
      std::istream is(&response_);
      if( is.peek() == 0xff )
	{
	  ready_state_ = CLOSED;
	  on_close();
	}
      else
	{
	  std::stringstream os;
	  while( is.peek() != 0xff ) os.put(is.get());
	  os << std::flush;
	  on_message( os.str() );
	  is.get(); // skip 0xff
	  
	  if(response_.size() > 0)
	    {
	      check_frame_type();
	    }
	  else
	    {
	      boost::asio::async_read(socket_, response_,
				      boost::asio::transfer_at_least(1),
				      boost::bind(&client::handle_read_frame_type, this,
						  boost::asio::placeholders::error));
	    }
	}
    }
  else
    {
      ready_state_ = CLOSED;
      on_error( err.value(), err.message() );
    }
}


void client::handle_write_text_frame(const boost::system::error_code& err)
{
  if (err)
    on_error( err.value(), err.message() );
}


}


