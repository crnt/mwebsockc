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
  std::string md5( const std::string& in );

  void insert_chars( std::string& str );
  void insert_spaces(int spaces, std::string& str);
  char get_char();

  random rand_;

  std::string key_1_;
  std::string key_2_;
  std::string key_3_;
  std::string expected_;

};



class url
{
public:

	bool parse(const std::string& raw);

	const std::string& raw() const { return protocol_; }

	const std::string& protocol() const { return protocol_; }
	const std::string& endpoint() const { return endpoint_; }
	const std::string& path() const { return path_; }
	const std::string& host() const { return host_; }
	const std::string& port() const { return port_; }

private:
	std::string raw_;

	std::string protocol_;
	std::string endpoint_;
	std::string path_;
	std::string host_;
	std::string port_;

};



class ihandler
{
public:
	virtual ~ihandler(){}

	virtual void on_open() = 0;
	virtual void on_message( const std::string& msg ) = 0;
	virtual void on_error( int error_code, const std::string& msg ) = 0;
	virtual void on_close() = 0;

};

class iclient
	: public ihandler
{
public:
	virtual ~iclient(){}

	virtual void on_raw_open() = 0;
	virtual void on_raw_message( const std::string& msg ) = 0;
	virtual void on_raw_error( int error_code, const std::string& msg ) = 0;
	virtual void on_raw_close() = 0;

};



template<typename AsyncStream>
class protocol
{
public:

	protocol( AsyncStream& socket, iclient& handler, url& url )
		:socket_(socket)
		,handler_(handler)
		,url_(url)
	{}



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

	void close()
	{
		std::ostream os(&request_);
		os.put(0x00);
		os.put(0x00);
		os.put(0xff);
		os.flush();

		boost::asio::async_write(socket_, request_,
			boost::bind(&protocol::handle_close, this,
				boost::asio::placeholders::error));

	}



private:

	static const int INVALID_RESPONSE = 2;
	static const int BAD_STATUS       = 3;
	static const int HANDSHAKE_FAILED = 4;
	static const int BAD_FRAME        = 5;


	websocket_key_generator key_gen_;

	boost::asio::streambuf request_;
	boost::asio::streambuf response_;

	AsyncStream& socket_;
	iclient& handler_;
	url& url_;


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
			handler_.on_raw_error( err.value(), err.message() );
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
				handler_.on_raw_error( INVALID_RESPONSE, "invailed response" );
				return;
			}

			if (status_code != 101)
			{
				handler_.on_raw_error( BAD_STATUS, "bad status" );
				return;
			}

			boost::asio::async_read_until(socket_, response_, "\r\n\r\n",
				boost::bind(&protocol::handle_read_headers, this,
				boost::asio::placeholders::error));
		}
		else
		{
			handler_.on_raw_error( err.value(), err.message() );
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
			handler_.on_raw_error( err.value(), err.message() );
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
			handler_.on_raw_error( err.value(), err.message() );
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
			handler_.on_raw_open();
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
			handler_.on_raw_error( HANDSHAKE_FAILED, "handshake failed" );
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
			handler_.on_raw_error( err.value(), err.message() );
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
			handler_.on_raw_error( BAD_FRAME, "bad frame" );
		}
			break;
		default:
		{
			handler_.on_raw_error( BAD_FRAME, "bad frame" );
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
				handler_.on_raw_close();
			}
			else
			{
				std::stringstream os;
				while( is.peek() != 0xff ) os.put(is.get());
				os << std::flush;
				handler_.on_raw_message( os.str() );
				is.get(); // skip 0xff

				if(response_.size() > 0)
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
		}
		else
		{
			handler_.on_raw_error( err.value(), err.message() );
		}
	}



	void handle_write_text_frame(const boost::system::error_code& err)
	{

		if (!err)
		{

			std::ostream os(&request_);
			os.put(0x00);
			os.put(0x00);
			os.put(0xff);
			os.flush();

			boost::asio::async_write(socket_, request_,
				boost::bind(&protocol::handle_write_text_frame_dummy, this,
					boost::asio::placeholders::error));

		}
		else
		{
			handler_.on_raw_error( err.value(), err.message() );
		}
	}

	void handle_write_text_frame_dummy(const boost::system::error_code& err)
	{
		if (err)
			handler_.on_raw_error( err.value(), err.message() );
	}



	void handle_close(const boost::system::error_code& err)
	{

		if (!err)
		{

			std::ostream os(&request_);
			os.put(0x00);
			os.put(0xff);
			os.flush();

			boost::asio::async_write(socket_, request_,
				boost::bind(&protocol::handle_close_dummy, this,
					boost::asio::placeholders::error));

		}
		else
		{
			handler_.on_raw_error( err.value(), err.message() );
		}

	}

	void handle_close_dummy(const boost::system::error_code& err)
	{
		socket_.lowest_layer().close();
		handler_.on_raw_close();
	}


};


//template<typename AsyncStream> void protocol<AsyncStream>::open(){}



class isession
{
public:
	virtual ~isession(){}

	virtual void close() = 0;
	virtual void send( const std::string& msg ) = 0;

};



class session
	:public isession
{
public:

	session(boost::asio::io_service& io_service,
	        iclient& handler,
	        url& url,
	        const std::string& protocol )
		:handler_(handler)
		,url_(url)
		,io_service_(io_service)
		,resolver_(io_service_)
		,socket_(io_service_)
		,protocol_(socket_, handler_, url_)
	{
		boost::asio::ip::tcp::resolver::query query(url_.host(), url_.port());
		resolver_.async_resolve(query,
			boost::bind(&session::handle_resolve, this,
				boost::asio::placeholders::error,
					boost::asio::placeholders::iterator));
	}



	virtual void send( const std::string& msg )
	{
		protocol_.send( msg );
	}



	virtual void close()
	{
		io_service_.post(boost::bind(&session::handle_close, this));
	}




private:
 	static const int INVALID_URI = 1;

	iclient& handler_;
	url url_;

	boost::asio::io_service& io_service_;

	boost::asio::ip::tcp::resolver resolver_;
	boost::asio::ip::tcp::socket socket_;
	protocol<boost::asio::ip::tcp::socket> protocol_;



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
			handler_.on_raw_error( err.value(), err.message() );
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
			handler_.on_raw_error( err.value(), err.message() );
		}
	}

	void handle_close()
	{
		protocol_.close();
	}

};


class ssl_session
	:public isession
{
public:
	typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_t;

	ssl_session(boost::asio::io_service& io_service,
	            boost::asio::ssl::context& context,
	            iclient& handler,
	            url& url,
	            const std::string& protocol)
		:handler_(handler)
		,url_(url)
		,io_service_(io_service)
		,resolver_(io_service_)
		,socket_(io_service_, context)
		,protocol_(socket_, handler_, url_)
	{

		boost::asio::ip::tcp::resolver::query query(url_.host(), url_.port());
		resolver_.async_resolve(query,
			boost::bind(&ssl_session::handle_resolve, this,
				boost::asio::placeholders::error,
					boost::asio::placeholders::iterator));
	}



	virtual void send( const std::string& msg )
	{
		protocol_.send( msg );
	}

	virtual void close()
	{
		io_service_.post(boost::bind(&ssl_session::handle_close, this));
	}



private:
  static const int INVALID_URI = 1;

	iclient& handler_;
	url url_;

	boost::asio::io_service& io_service_;

	boost::asio::ip::tcp::resolver resolver_;
	socket_t socket_;
	protocol<socket_t> protocol_;



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
			handler_.on_raw_error( err.value(), err.message() );
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
			handler_.on_raw_error( err.value(), err.message() );
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
			handler_.on_raw_error( err.value(), err.message() );
		}
	}

	void handle_close()
	{
		protocol_.close();
	}


};




class client
	: public iclient
{
public:

	static const int CONNECTING = 0;
	static const int OPEN       = 1;
	static const int CLOSING    = 2;
	static const int CLOSED     = 3;


	client( boost::asio::ssl::context::method ssl_method
	         = boost::asio::ssl::context::sslv3 )
		:ready_state_(CLOSED)
		,ssl_context_( io_service_, ssl_method )
	{
	}

	virtual ~client(){}

	int ready_state() const { return ready_state_; }

	void connect(const std::string& url, const std::string& protocol = "")
	{
		ready_state_ = CONNECTING;

		if(url_.parse(url))
		{
			/* do nothing */
		}

		if(url_.protocol() == "ws")
		{
			p_session_.reset(
				new session(io_service_, *this, url_, protocol));
		}
		else if(url_.protocol() == "wss")
		{
			if( ssl_verify_file_.length() == 0 )
			{
				ssl_context_
					.set_verify_mode(boost::asio::ssl::context::verify_none);
			}
			else
			{
				ssl_context_
					.set_verify_mode(boost::asio::ssl::context::verify_peer);
				ssl_context_
					.load_verify_file(ssl_verify_file_);
			}

			p_session_.reset(
				new ssl_session(
					io_service_, ssl_context_, *this, url_, protocol));
		}

		io_service_.reset();
		boost::thread(
			boost::bind(&boost::asio::io_service::run, &io_service_));

	}

	void send(const std::string& msg)
	{
		p_session_.get()->send(msg);
	}

	void close()
	{
		ready_state_ = CLOSING;
		p_session_.get()->close();
	}

	void set_ssl_verify_file(const std::string& name)
	{
		ssl_verify_file_ = name;
	}


	virtual void on_raw_open()
	{
		ready_state_ = OPEN;
		on_open();
	}

	virtual void on_raw_message( const std::string& msg)
	{
		on_message(msg);
	}

	virtual void on_raw_error( int error_code, const std::string& msg )
	{
		on_error(error_code, msg);
	}

	virtual void on_raw_close()
	{
		ready_state_ = CLOSED;
		on_close();
	}

private:
	url url_;
	int ready_state_;

	std::string ssl_verify_file_;

	boost::asio::io_service io_service_;
	boost::asio::ssl::context ssl_context_;

	std::auto_ptr<isession> p_session_;

};



}



#endif
