all:
	mkdir -p build
	gcc -fdiagnostics-color=always -g -O0 src/main.c -o build/task3
clean:
	rm build/task3