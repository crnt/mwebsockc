#ifndef __MWEBSOCK_WEBSOCKET_CLIENT__
#define __MWEBSOCK_WEBSOCKET_CLIENT__


#include <string>
#include <boost/random.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace mwebsock
{


class random
{
public:

  random();
  unsigned int next_int(unsigned int max);

private:

  boost::mt19937 gen;

};



class url
{
public:

  url();
  url(const std::string& raw);

  void parse();
  void parse(const std::string& raw);

  const std::string& raw() const;

  const std::string& protocol() const;
  const std::string& endpoint() const;
  const std::string& path() const;
  const std::string& host() const;
  const std::string& port() const;


private:
  std::string raw_;

  std::string protocol_;
  std::string endpoint_;
  std::string path_;
  std::string host_;
  std::string port_;

};

class url_exception : public std::domain_error {
public:
  url_exception( const std::string& cause )
    : std::domain_error( cause ) {}
};


class websocket_key_generator
{
public:

  websocket_key_generator();

  const std::string& key_1() const;
  const std::string& key_2() const ;
  const std::string& key_3() const;
  const std::string& expected() const;

private:

  std::string gen_key(int spaces, int number);
  std::string gen_bytes();
  std::string md5(const std::string& in );

  void insert_chars( std::string& str );
  void insert_spaces(int spaces, std::string& str);
  char get_char();

  random rand_;

  std::string key_1_;
  std::string key_2_;
  std::string key_3_;
  std::string expected_;

};




class client_impl;

class client_handler
{
public:
  void set_client(client_impl* client)
  {
    client_ = client;
  }

  virtual void on_message( const std::string& msg) = 0;
  virtual void on_open() = 0;
  virtual void on_close() = 0;
  virtual void on_error( int error_code, const std::string& msg ) = 0;

protected:
  client_impl* client_;

};


class client_impl
{
public:
  static const int CONNECTING = 0;
  static const int OPEN = 1;
  static const int CLOSING = 2;
  static const int CLOSED = 3;
  
  client_impl(client_handler& handler, const std::string& url, const std::string& protocol = "");

  void close();
  void send(const std::string& msg);

  int ready_state() const;
  
private:
  static const int INVALID_URI = 1;
  static const int INVALID_RESPONSE = 2;
  static const int BAD_STATUS = 3;
  static const int HANDSHAKE_FAILED = 4;
  static const int BAD_FRAME = 5;

  void handle_resolve(const boost::system::error_code& err,
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator);

  void handle_connect(const boost::system::error_code& err,
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator);

  void handle_write_request(const boost::system::error_code& err);

  void handle_read_status_line(const boost::system::error_code& err);

  void handle_read_headers(const boost::system::error_code& err);

  void handle_read_key(const boost::system::error_code& err);

  void handle_read_frame_type(const boost::system::error_code& err);

  void handle_read_text_frame(const boost::system::error_code& err);
  //  void handle_read_binary_frame(const boost::system::error_code& err);

  void handle_write_text_frame(const boost::system::error_code& err);

  void check_handshake();
  void check_frame_type();

  int ready_state_;

  client_handler& handler_;

  url url_;
  websocket_key_generator key_gen_;

  boost::asio::io_service io_service_;

  boost::asio::ip::tcp::resolver resolver_;
  boost::asio::ip::tcp::socket socket_;

  boost::asio::streambuf request_;
  boost::asio::streambuf response_;

  boost::thread* thread_;

};


class client
  :public client_handler
{
public:
  client();
 
  void connect(const std::string& url, const std::string& protocol = "");
  void close();
  void send(const std::string& msg);

  int ready_state() const;

  virtual void on_message( const std::string& msg) = 0;
  virtual void on_open() = 0;
  virtual void on_close() = 0;
  virtual void on_error( int error_code, const std::string& msg ) = 0;

private:
  client_impl* client_impl_;

};




class isession
{
public:
	virtual ~isession(){}

	virtual void close() = 0;
	virtual void send( const std::string& msg ) = 0;
	virtual int ready_state() const = 0;

};


class ihandler
{
public:
	virtual ~ihandler(){}

	virtual void on_message( const std::string& msg) = 0;
	virtual void on_open() = 0;
	virtual void on_close() = 0;
	virtual void on_error( int error_code, const std::string& msg ) = 0;

	void set_client(isession* client)
	{
		client_ = client;
	}

protected:
	isession* client_;

};



template<typename AsyncStream>
class protocol
{
public:

	protocol(AsyncStream& socket, ihandler& handler, url& url )
		:socket_(socket)
		,handler_(handler)
		,url_(url)
	{}

	void close()
	{
		std::ostream os(&request_);
		os.put(0x00);
		os.put(0xff);
		os.flush();

		// synchronized operation
		boost::asio::write(socket_, request_);

	}

	void send( const std::string& msg )
	{
		std::ostream os(&request_);
		os.put(0x00);
		os << msg;
		os.put(0xff);
		os.flush();

		boost::asio::async_write(socket_, request_,
		     boost::bind(&protocol::handle_write_text_frame, this,
		     boost::asio::placeholders::error));

	}

	void open()
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
		     boost::bind(&protocol::handle_write_request, this,
		     boost::asio::placeholders::error));

	}


	void handle_write_request(const boost::system::error_code& err)	
	{
	  if (!err)
	    {
	      boost::asio::async_read_until(socket_, response_, "\r\n",
			    boost::bind(&protocol::handle_read_status_line, this,	
			   boost::asio::placeholders::error));
	    }
	  else
	    {
	      handler_.on_error( err.value(), err.message() );
	    }
	}
	
	void handle_read_status_line(const boost::system::error_code& err)
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
		  handler_.on_error( INVALID_RESPONSE, "invailed response" );
		  return;
		}
	      if (status_code != 101)
		{
		  handler_.on_error( BAD_STATUS, "bad status" );
		  return;
		}
	
	      boost::asio::async_read_until(socket_, response_, "\r\n\r\n",
					    boost::bind(&protocol::handle_read_headers, this,
							boost::asio::placeholders::error));
	    }
	  else
	    {
	      handler_.on_error( err.value(), err.message() );
	    }
	}
	
	void handle_read_headers(const boost::system::error_code& err)
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
					  boost::bind(&protocol::handle_read_key, this,
						      boost::asio::placeholders::error));
		}
	    }
	  else
	    {
	      handler_.on_error( err.value(), err.message() );
	    }
	}
	
	void handle_read_key(const boost::system::error_code& err)
	{
	  if (!err)
	    {
	      check_handshake();
	    }
	  else
	    {
	      handler_.on_error( err.value(), err.message() );
	    }
	}
	
	void check_handshake()
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
	      handler_.on_open();
	      if( response_.size() > 0 )
		{
		  check_frame_type();
		}
	      else
		{
		  boost::asio::async_read(socket_, response_,
					  boost::asio::transfer_at_least(1),
					  boost::bind(&protocol::handle_read_frame_type, this,
						      boost::asio::placeholders::error));
		}
	    }
	  else
	    {
	      handler_.on_error( HANDSHAKE_FAILED, "handshake failed" );
	    }
	
	}
		
	void handle_read_frame_type(const boost::system::error_code& err)
	{
	  if (!err)
	    {
	      check_frame_type();
	    }
	  else
	    {
	      handler_.on_error( err.value(), err.message() );
	    }
	}
	
	void check_frame_type()
	{
	  std::istream is(&response_);
	
	  switch( is.get() )
	    {
	    case 0x00:
	      {
		boost::asio::async_read_until(socket_, response_, 0xff,
					      boost::bind(&protocol::handle_read_text_frame, this	,
							  boost::asio::placeholders::error));
	      }
	      break;
	    case 0x80:
	      {
		/* binary frame */
		handler_.on_error( BAD_FRAME, "bad frame" );
	      }
	      break;
	    default:
	      {
		handler_.on_error( BAD_FRAME, "bad frame" );
	      }
	      break;
	    }
	
	}
	
	void handle_read_text_frame(const boost::system::error_code& err)
	{
	  if (!err)
	    {
	      std::istream is(&response_);
	      if( is.peek() == 0xff )
		{
		  handler_.on_close();
		}
	      else
		{
		  std::stringstream os;
		  while( is.peek() != 0xff ) os.put(is.get());
		  os << std::flush;
		  handler_.on_message( os.str() );
		  is.get(); // skip 0xff
		  
		  if(response_.size() > 0)
		    {
		      check_frame_type();
		    }
		  else
		    {
		      boost::asio::async_read(socket_, response_,
					      boost::asio::transfer_at_least(1),
					      boost::bind(&protocol::handle_read_frame_type, this	,
							  boost::asio::placeholders::error));
		    }
		}
	    }
	  else
	    {
	      handler_.on_error( err.value(), err.message() );
	    }
	}
	
	
	void handle_write_text_frame(const boost::system::error_code& err)
	{
	  if (err)
	    handler_.on_error( err.value(), err.message() );
	}





private:

  static const int INVALID_RESPONSE = 2;
  static const int BAD_STATUS = 3;
  static const int HANDSHAKE_FAILED = 4;
  static const int BAD_FRAME = 5;


	websocket_key_generator key_gen_;

	boost::asio::streambuf request_;

	boost::asio::streambuf response_;

	AsyncStream& socket_;
	ihandler& handler_;
	url& url_;



};

class session
	:public isession
{
public:
	static const int CONNECTING = 0;
	static const int OPEN = 1;
	static const int CLOSING = 2;
	static const int CLOSED = 3;

	session(boost::asio::io_service& io_service,
	        ihandler& handler,
	        url& url,
	        const std::string& protocol )
		:ready_state_(CLOSED)
		,handler_(handler)
		,url_(url)
		,io_service_(io_service)
		,resolver_(io_service_)
		,socket_(io_service_)
		,protocol_(socket_, handler_, url_)
	{
		handler_.set_client(this);

		boost::asio::ip::tcp::resolver::query query(url_.host(), url_.port());
		resolver_.async_resolve(query,
		          boost::bind(&session::handle_resolve, this,
		          boost::asio::placeholders::error,
		          boost::asio::placeholders::iterator));
	}

	virtual void close()
	{
		protocol_.close();
	}


	virtual void send( const std::string& msg )
	{
		protocol_.send( msg );
	}

	virtual int ready_state() const { return ready_state_; }

	void handle_resolve(const boost::system::error_code& err,
	    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
	  if (!err)
	    {
	      boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
	      socket_.lowest_layer().async_connect(endpoint,
			    boost::bind(&session::handle_connect, this,
					boost::asio::placeholders::error, ++endpoint_iterator));
	    }
	  else
	    {
	      ready_state_ = CLOSED;
	      handler_.on_error( err.value(), err.message() );
	    }
	}

	void handle_connect(const boost::system::error_code& err,
	    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
	  if (!err)
	    {
			protocol_.open();
	    }
	  else if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator())
	    {

	      socket_.lowest_layer().close();
	      boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
	      socket_.lowest_layer().async_connect(endpoint,
			    boost::bind(&session::handle_connect, this,
			    boost::asio::placeholders::error, ++endpoint_iterator));
	    }
	  else
	    {
	      ready_state_ = CLOSED;
	      handler_.on_error( err.value(), err.message() );
	    }
	}



private:
 	static const int INVALID_URI = 1;

	int ready_state_;
	ihandler& handler_;
	url url_;

	boost::asio::io_service& io_service_;

	boost::asio::ip::tcp::resolver resolver_;
	boost::asio::ip::tcp::socket socket_;
	protocol<boost::asio::ip::tcp::socket> protocol_;


};


class ssl_session
	:public isession
{
public:
	typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_t;

	static const int CONNECTING = 0;
	static const int OPEN = 1;
	static const int CLOSING = 2;
	static const int CLOSED = 3;

	ssl_session(boost::asio::io_service& io_service,
	            boost::asio::ssl::context& context,
	            ihandler& handler,
	            url& url,
	            const std::string& protocol)
		:ready_state_(CLOSED)
		,handler_(handler)
		,url_(url)
		,io_service_(io_service)
		,resolver_(io_service_)
		,socket_(io_service_, context)
		,protocol_(socket_, handler_, url_)
	{
	  handler_.set_client(this);

	  boost::asio::ip::tcp::resolver::query query(url_.host(), url_.port());
	  resolver_.async_resolve(query,
					  boost::bind(&ssl_session::handle_resolve, this,
				      boost::asio::placeholders::error,
				      boost::asio::placeholders::iterator));
	}

	virtual void close()
	{
		protocol_.close();
	}


	virtual void send( const std::string& msg )
	{
		protocol_.send( msg );
	}

	virtual int ready_state() const { return ready_state_; }


	void handle_resolve(const boost::system::error_code& err,
	    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
	  if (!err)
	    {
	      boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
	      socket_.lowest_layer().async_connect(endpoint,
			    boost::bind(&ssl_session::handle_connect, this,
					boost::asio::placeholders::error, ++endpoint_iterator));
	    }
	  else
	    {
	      ready_state_ = CLOSED;
	      handler_.on_error( err.value(), err.message() );
	    }
	}

	void handle_connect(const boost::system::error_code& err,
	    boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
	  if (!err)
	    {
           socket_.async_handshake(boost::asio::ssl::stream_base::client,
               boost::bind(&ssl_session::handle_handshake, this,
               boost::asio::placeholders::error));
	    }
	  else if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator())
	    {

	      socket_.lowest_layer().close();
	      boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
	      socket_.lowest_layer().async_connect(endpoint,
			    boost::bind(&ssl_session::handle_connect, this,
			    boost::asio::placeholders::error, ++endpoint_iterator));
	    }
	  else
	    {
	      ready_state_ = CLOSED;
	      handler_.on_error( err.value(), err.message() );
	    }
	}

   void handle_handshake(const boost::system::error_code& err)
  {
    if (!err)
    {
			protocol_.open();
    }
    else
    {
	      ready_state_ = CLOSED;
	      handler_.on_error( err.value(), err.message() );
    }
  }


private:
  static const int INVALID_URI = 1;

	int ready_state_;
	ihandler& handler_;
	url url_;

	boost::asio::io_service& io_service_;

	boost::asio::ip::tcp::resolver resolver_;
	socket_t socket_;
	protocol<socket_t> protocol_;

};




class nclient
  :public ihandler
{
public:
	nclient()
	{
	}

	virtual ~nclient(){}

	void connect(const std::string& url, const std::string& protocol = "")
	{
		try
		{
			url_.parse(url);
		}
		catch (const url_exception&)
		{
			/* do nothing */
		}

		p_io_service_.reset(new boost::asio::io_service());

		if(url_.protocol() == "ws")
		{
			p_session_.reset(
			       new session(*(p_io_service_.get()), *this, url_, protocol));
		}
		else if(url_.protocol() == "wss")
		{
			p_context_.reset(
			  new boost::asio::ssl::context(
			    *(p_io_service_.get()), boost::asio::ssl::context::sslv3));
//			p_context_.get()
//			  ->set_verify_mode(boost::asio::ssl::context::verify_none);
			p_context_.get()
			  ->set_verify_mode(boost::asio::ssl::context::verify_peer);
			p_context_.get()
			  ->load_verify_file(verify_file_);

			p_session_.reset(
			  new ssl_session(
			    *(p_io_service_.get()), *(p_context_.get()),
			    *this, url_, protocol));
		}

		boost::thread(boost::bind(
		    &boost::asio::io_service::run, p_io_service_.get()));

	}

	void close()
	{
		p_session_.get()->close();
		p_io_service_.get()->stop();

		p_session_.reset();
		p_context_.reset();
		p_io_service_.reset();
	}

	void send(const std::string& msg)
	{
		p_session_.get()->send(msg);
	}

	int ready_state() const
	{
		if( p_session_.get() == NULL)
			return session::CLOSED;
		else
			return p_session_.get()->ready_state();

	}

	void set_verify_file(const std::string& name)
	{
		verify_file_ = name;
	}

	virtual void on_message( const std::string& msg) = 0;
	virtual void on_open() = 0;
	virtual void on_close() = 0;
	virtual void on_error( int error_code, const std::string& msg ) = 0;

private:
	url url_;
	std::string verify_file_;

	std::auto_ptr<boost::asio::io_service> p_io_service_;
	std::auto_ptr<boost::asio::ssl::context> p_context_;
	std::auto_ptr<isession> p_session_;

};



}



#endif
