all:
	mkdir -p build
	gcc -fdiagnostics-color=always -g -O0 src/main.c -lz -o build/task3
clean:
	rm build/task3