#ifndef __MWEBSOCK_WEBSOCKET_CLIENT__
#define __MWEBSOCK_WEBSOCKET_CLIENT__


#include <string>
#include <boost/random.hpp>
#include <boost/asio.hpp>


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

  url(const std::string& raw);

  void parse();

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
  //  void handle_close(const boost::system::error_code& err);

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


};


class client
  :public client_handler
{
public:
 
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



}



#endif
