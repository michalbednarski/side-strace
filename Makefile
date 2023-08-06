all: sidestrace sidestraceside.so sidestracestrace.so

clean:
	rm -f sidestrace sidestraceside.so sidestracestrace.so

sidestrace: sidestracelauncher.c
	gcc -Wno-deprecated-declarations $< -o $@

sidestraceside.so: sidestraceside.c preloadcommon.h
	gcc -shared -fPIC $< -o $@ -ldl

sidestracestrace.so: sidestracestrace.c preloadcommon.h
	gcc -shared -fPIC $< -o $@ -ldl
