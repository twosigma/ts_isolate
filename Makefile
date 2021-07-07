ALL := ts_isolate.so ts_isolate_make.so ts_isolate py_ts_isolate.so
CFLAGS := -O3

all: ${ALL}

ts_isolate.so: ts_isolate.c
	${CC} -fPIC -shared ${CFLAGS} ${CPPFLAGS} ${LDFLAGS} -o $@ $<

%.so: %.c ts_isolate.so
	${CC} -fPIC -shared ${CFLAGS} ${CPPFLAGS} ${LDFLAGS} -o $@ $< -L. -Wl,-rpath,\$${ORIGIN} -l:ts_isolate.so

ts_isolate: ts_isolate_cli.c ts_isolate.so
	${CC} ${CFLAGS} ${CPPFLAGS} ${LDFLAGS} -o $@ $< -L. -Wl,-rpath,\$${ORIGIN} -l:ts_isolate.so

clean:
	${RM} ${ALL}
