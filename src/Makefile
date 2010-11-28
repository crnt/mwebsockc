.SUFFIXES: .o .c .cpp .m .mm

ifeq ($(BUILD),)
	BUILD = debug
endif

ifeq ($(BUILD), release)
	CL_OPTS = \
		-O2

	LINK_OPTS = \
		-O2

else
	CL_OPTS = \


	LINK_OPTS = \
		-g

endif


all: \
	libmwebsockc.a


libmwebsockc.a: \
		prep \
		md5c.o \
		websocket_client.o
	ar rcs \
		../dist/libmwebsockc.a \
		md5c.o \
		websocket_client.o
	ranlib \
		../dist/libmwebsockc.a


mddriver: \
		prep \
		md5c.o \
		mddriver.o
	gcc \
		-o ../dist/mddriver \
		$(LINK_OPTS) \
		md5c.o \
		mddriver.o


.c.o:
	gcc \
		-x c \
		-c \
		-g \
		-Wall \
		-I/usr/local/include \
		-I../include \
		$(CL_OPTS) \
		-o $*.o \
		$*.c


.cpp.o:
	gcc \
		-x c++ \
		-c \
		-g \
		-Wall \
		-I/usr/local/include \
		-I../include \
		$(CL_OPTS) \
		-o $*.o \
		$*.cpp


prep:
	mkdir -p ../dist


clean:
	rm -f *.o
	rm -f ../dist/libmwebsockc.a
	rm -f ../dist/mddriver

