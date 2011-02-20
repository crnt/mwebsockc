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
	test \



test: \
		test.o
	gcc \
		-o ../dist/test \
		-lstdc++ \
		-lboost_system \
		-lboost_thread \
		-lssl \
		-lcrypto \
		$(LINK_OPTS) \
		../dist/libmwebsockc.a \
		test.o


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
	mkdir -f ../dist


clean:
	rm -f *.o
	rm -f ../dist/test


