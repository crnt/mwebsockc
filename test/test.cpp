#include <iostream>
#include "websocket_client.hpp"


class chat_client
  : public mwebsock::client
{
public:
  chat_client( const std::string& name )
    : mwebsock::client("ws://mitsuwo.shizentai.jp:8080/mchat/ws")
    ,name_(name)
  {}
 
  void on_message( const std::string& msg)
  {
    std::cout << msg << std::endl;
  }

  void on_open()
  {
    this->send("c:" + name_);
    std::cout << ">> server connected." << std::endl;
  }

  void on_close()
  {
    std::cout << ">> server closed." << std::endl;
  }

  void on_error( int error_code, const std::string& msg )
  {
    std::cout << "error:" << msg << std::endl;
  }
private:
  std::string name_;
};


int main(int argc, char** argv)
{
  if( argc < 2 ) 
    {
      std::cout << "test [user_name]" << std::endl;
      return 1;
    }

  try
    {
      chat_client cl(argv[1]);
      cl.connect();

      std::string line;
      while(std::getline(std::cin, line ))
      {
	char c = line.at(0);

	switch(c)
	  {
	  case 'q':
	    {
	      cl.close();
	      std::cout << ">> client closed." << std::endl;
	      return 0;
	    }
	    break;
	  default:
	    {
	      cl.send("m:" + line );
	    }
	      break;
	 }

      }

    }
  catch (std::exception& e)
    {
      std::cout << "Exception: " << e.what() << "\n";
    }

  return 0;

 
}
